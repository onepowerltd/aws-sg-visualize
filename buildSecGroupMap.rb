#!/usr/local/bin/ruby
require 'json'
require 'fog'
require 'digest/md5'
require 'graph'
require 'mixlib/cli'

class Options
  include Mixlib::CLI
  option :region, :short =>'-r REGION', :long => '--region REGION',:default => 'us-west-2',:description => "AWS Region for which to describe Security groups"
  option :srcre, :short => '-s SRC', :long => '--source SOURCE', :default => '.*', :description => 'Regexp to filter results to match by Source IP/Groups/Groupname. Default is to match all.'
  option :dstre, :short => '-d DEST', :long => '--dest DEST', :default => '.*', :description => 'Regexp to filter results to match by Destination SecGroup. Default is to match all.'
  option :help, :short =>'-h', :long => '--help', :boolean => true, :default => false, :description => "Show this Help message.", :show_options => true, :exit => 0
  option :nograph, :short =>'-n', :long => '--nograph', :boolean => true, :default => false,:description => "Disable PNG/SVG object generation. False by default."
  option :json, :short => '-j', :long => '--json', :boolean => true, :default => false, :description => "Dump the JSON from which SVG/PNG is built"
  option :filename, :short => '-f FILENAME', :long => '--filename FILENAME', :default => "/tmp/sgmap", :description => "Filename (no svg/png suffix) to dump map into. Defaults to /tmp/sgmap(.svg)"
  option :format, :short => '-m FORMAT', :long => '--mode FORMAT', :default => 'svg', :description => "svg/png only - For generated graph. Defaults to svg"
end

class ColorRand
	def initialize
		@used=Hash.new
	end

	def getNext
		thiscol="%06x" % (rand * 0xffffff)
		while ( @used.has_key?(thiscol))
			thiscol="%06x" % (rand * 0xffffff)
		end		
		return "color = \"##{thiscol}\""
	end
end

ELBDESC='amazon-elb-sg'
ANYWHERE='0.0.0.0/0'

def md5(str="")
	return Digest::MD5.hexdigest(str)
end

def getGroupDesc(x=Hash.new)
	return (x.has_key?('groupName') && !x['groupName'].empty? ? "#{x['groupId']} (#{x['groupName']})" : "#{x['groupId']}")
end

def getSubnetDesc(x="")
	ret="NA"
	if x.nil? || x.empty?
		ret="NA"
	else	
		ip, maskbits = x.split('/')
		if maskbits.to_i==32 #Bah, assuming ipv4 only for now.
			ret="Host #{ip}"
		else
			ret="IP-Subnet #{ip}/#{maskbits}"
		end
	end
	return ret
end

def groupByProto(x=Array.new)
	grouped=Hash.new
	x.each do |thispp|
		proto, port = thispp.split(":")
		proto.upcase!
		port=(port.nil? || port.empty?) ? "ANY" : port.to_i
		grouped[proto]=[] unless grouped.has_key?(proto)
		grouped[proto].push(port)
	end
	str=grouped.keys.map {|y| "#{y}[#{grouped[y].sort{|a1,a2| a1<=>a2}.join(",")}]"}.join(" ")
	return str
end

def describe_ec2_secgroup(region="")
	fogobj = Fog::Compute.new(
		:provider => 'AWS',
		:region => region,
		:aws_access_key_id => ENV['AWS_ACCESS_KEY_ID'],
		:aws_secret_access_key => ENV['AWS_SECRET_ACCESS_KEY']
	)
	begin
		$stderr.puts "Describing EC2 security groups..."
		return fogobj.describe_security_groups.body['securityGroupInfo'].reject {|x| x['groupName']=~/OpsWorks/ || x['ipPermissions'].length==0}
	rescue Exception => e
		abort "Failed to fetch EC2 sec groups! - #{e.inspect}"
	end		
end

def describe_cache_secgroup(region="")
	fogobj=Fog::AWS::Elasticache.new(
		:region => region,
		:aws_access_key_id => ENV['AWS_ACCESS_KEY_ID'],
		:aws_secret_access_key => ENV['AWS_SECRET_ACCESS_KEY']
	)
	begin
		$stderr.puts "Describing Elastic Cache Security groups..."
		return fogobj.describe_cache_security_groups.body['CacheSecurityGroups']
	rescue Exception => e
		abort "Failed to fetch Elastic Cache security groups! - #{e.inspect}"
	end
end

### Work starts here...

#Parse cmdline opts.
cli=Options.new
cli.parse_options

THISREGION=cli.config[:region]
SrcRe=Regexp.new(cli.config[:srcre])
DstRe=Regexp.new(cli.config[:dstre])
abort "No region specified in config." if THISREGION.nil?

ec2sec=describe_ec2_secgroup(THISREGION)
cachesec=describe_cache_secgroup(THISREGION)

sghash=Hash.new #sg-xxx => sg-description
allsources=Hash.new
cachesecmap=Hash.new #Elastic cache sec groups use lower case description of EC2 sec group name and not its ID :-( So map desc.lowcase -> sg-xxxx

colorctr=0
#First process all EC2 security group info.
ec2sec.each do |thisg|
	colorctr+=1
	tgtgroupdesc=getGroupDesc(thisg)
	sghash[ thisg['groupId' ] ]=tgtgroupdesc
	cachesecmap[ thisg['groupName'].downcase ] = thisg['groupId']	#well, >1 groups could have the same description... :-(
	next unless tgtgroupdesc.match(DstRe)
	thisg['ipPermissions'].each do |this_allowed|
		proto_port_combo=this_allowed['ipProtocol']+":"+this_allowed['toPort'].to_s
		proto_port_combo="ANY" if proto_port_combo=="-1:"
		#The "source" could be either a IP subnet or another security group.
		this_allowed['groups'].each do |x|
			colorctr+=1
			#srcid=getGroupDesc(x)	
			if x.has_key?('userId') && x['userId']=='amazon-elb'
				sghash[ x['groupId' ] ]=x['groupId'] + " (#{ELBDESC})"
			end
			srcid=x['groupId']
			next unless srcid.match(SrcRe)
			allsources[srcid]={'allowed_into'=>Hash.new} unless allsources.has_key?(srcid)
			allsources[srcid]['allowed_into'][tgtgroupdesc]=[] unless allsources[srcid]['allowed_into'].has_key?(tgtgroupdesc)
			allsources[srcid]['allowed_into'][tgtgroupdesc].push(proto_port_combo)			
		end	
		this_allowed['ipRanges'].each do |y|
			colorctr+=1
			srcid=getSubnetDesc(y['cidrIp'])
			next unless srcid.match(SrcRe)
			allsources[srcid]={'allowed_into'=>Hash.new} unless allsources.has_key?(srcid)
			allsources[srcid]['allowed_into'][tgtgroupdesc]=[] unless allsources[srcid]['allowed_into'].has_key?(tgtgroupdesc)
			allsources[srcid]['allowed_into'][tgtgroupdesc].push(proto_port_combo)
		end				
	end	
end


#Now process the elastic cache security groups too
cachesec.each do |thiscgrp|
	colorctr+=1
	gname=thiscgrp['CacheSecurityGroupName']
	thiscgrp['EC2SecurityGroups'].each do |ec2grp|
		name=ec2grp['EC2SecurityGroupName']
		id=cachesecmap.has_key?(name) ? cachesecmap[name] : name
		allsources[id]={'allowed_into' => Hash.new} unless allsources.has_key?(id)
		allsources[id]['allowed_into']['CacheGrp:'+name]=[] unless allsources[id]['allowed_into'].has_key?('CacheGrp:'+name)
		allsources[id]['allowed_into']['CacheGrp:'+name].push('cache')	
	end	
end

puts JSON.pretty_generate(allsources) if cli.config[:json]
if cli.config[:nograph]
	$stderr.puts "Skipping SVG/PNG generation since nograph was set"
	exit
end

colors=ColorRand.new
colmap=Hash.new

#Try to graph it. Each key in allsources will be a node
digraph do
	orient "LR"
	label "Security Groups in #{THISREGION.upcase}"
	allsources.keys.sort.each do |thissrc|
		srcdesc=sghash.has_key?(thissrc) ? sghash[thissrc] : thissrc
		#colmap[srcdesc]=send(colors.getNext) unless colmap.has_key?(srcdesc)  
		colmap[srcdesc]=colors.getNext
		n=node(srcdesc)
		n.attributes << colmap[srcdesc]
		if srcdesc=~/^Host |^IP-Subnet /
			n.attributes << bold + diagonals
			mdiamond << n
		elsif srcdesc=~/amazon-elb-sg/
			n.attributes << bold
			box3d << n
		elsif srcdesc=~/^CacheGrp/ #In hindsight, elastic cache sec group wont ever be a source
			n.attributes << trapezium
		else
			n.attributes << solid + parallelogram
		end
		allsources[thissrc]['allowed_into'].keys.sort.each do |thistgt|
			thistgtdesc=sghash.has_key?(thistgt) ? sghash[thistgt] : thistgt
			note=groupByProto(allsources[thissrc]['allowed_into'][thistgt])
			t=node(thistgtdesc)
			if thistgtdesc=~/^CacheGrp:/
				t.attributes << trapezium + bold
			else
				#colmap[thistgtdesc]=send(colors.getNext) unless colmap.has_key?(thistgt)
				colmap[thistgtdesc]=colors.getNext
				t.attributes << colmap[thistgtdesc] 
				t.attributes << filled
			end
			edge(srcdesc, thistgtdesc).label(note).attributes << colmap[srcdesc] #Edge set to same color as SRC
		end		
	end
	#x=node("srinivas")
	#x.attributes << "color = \"#B4639D\""
	#x.attributes << "style = striped"
	save cli.config[:filename], cli.config[:format]
end

$stderr.puts "Wrote map to #{cli.config[:filename]}.#{cli.config[:format]}"
