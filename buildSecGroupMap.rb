#!/usr/local/bin/ruby
require 'json'
require 'fog'
require 'digest/md5'
require 'graph'
require 'mixlib/cli'

#We could build list from describe-regions, but that would be another call. Use this list if user provides none.
ALLREGIONS="eu-west-1,sa-east-1,us-east-1,ap-northeast-1,us-west-2,us-west-1,ap-southeast-1,ap-southeast-2"

class Options
  include Mixlib::CLI
  option :region, :short =>'-r REGION', :long => '--region REGION',:default => 'us-west-2',:description => "AWS Region for which to describe Security groups. Defaults to us-west-2"
  option :srcre, :short => '-s SRC', :long => '--source SOURCE', :default => '.*', :description => 'Regexp to filter results to match by Source IP/Groups/Groupname. Default is to match all.'
  option :dstre, :short => '-d DEST', :long => '--dest DEST', :default => '.*', :description => 'Regexp to filter results to match by Destination Group name. Default is to match all.'
  option :help, :short =>'-h', :long => '--help', :boolean => true, :default => false, :description => "Show this Help message.", :show_options => true, :exit => 0
  option :nograph, :short =>'-n', :long => '--nograph', :boolean => true, :default => false,:description => "Disable PNG/SVG object generation. False by default."
  option :json, :short => '-j', :long => '--json', :boolean => true, :default => false, :description => "Dump the JSON from which SVG/PNG is built"
  option :filename, :short => '-f FILENAME', :long => '--filename FILENAME', :default => "/tmp/sgmap", :description => "Filename (no svg/png suffix) to dump map into. Defaults to /tmp/sgmap(.svg)"
  option :format, :short => '-m FORMAT', :long => '--mode FORMAT', :default => 'svg', :description => "svg/png only - For generated graph. Defaults to svg"
	option :no_ecache, :long => '--ecache-disable', :boolean => true, :default => false, :description => "Set to disable describing Elastic Cache security groups"
	option :no_rds, :long => '--rds-disable', :boolean => true, :default => false, :description => "Set to disable describing RDS security groups"
	option :allregions, :long => '--allregions us-west-1,us-east-1', :default => ALLREGIONS, :description => "Comma separated list of AWS regions you want to poll for elastic IP mappings"	
	option :no_meta, :long => '--no_meta', :boolean => true, :default => false, :description => "Disables EC2 instance meta-data fetch (To resolve elastic IPs to ec2 host). Defaults to false"
end

#Generate a new color each time so colors in SVG/PNG never repeat - Colors should be somewhat light...
class ColorRand
	def initialize(tot=1729) #1729 ? :-)
		@used=Hash.new
	end
	def getCol
		return (0..2).map{"%0x" % (rand * 0x80 + 0x80)}.join
	end
	def getNext
		thiscol=getCol
		while ( @used.has_key?(thiscol))
			thiscol=getCol
		end	
		@used[thiscol]=nil	
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

#This is a little crude when trying to map IP to a (maybe) known Elastic IP.
def getSubnetDesc(x="",ipmap=Hash.new)
	ret="NA"
	if x.nil? || x.empty?
		ret="NA"
	else	
		ip, maskbits = x.split('/')
		if maskbits.to_i==32 #Bah, assuming ipv4 only for now.
			ret=ipmap.has_key?(ip) ? "EC2 #{ipmap[ip]}" : "Host #{ip}"
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

def describe_elasticips(regionlist="",instanceinfo=true)
	eiphash=Hash.new #IP => "region:instanceid", instanceid may be NA for eip thats not mapped to an instance.
	regionlist.split(',').each do |thisr|
		rhash=Hash.new
		thisr.gsub!(/\s/,'')
		fogobj = Fog::Compute.new(
			:provider => 'AWS',:region => thisr,
			:aws_access_key_id => ENV['AWS_ACCESS_KEY_ID'],:aws_secret_access_key => ENV['AWS_SECRET_ACCESS_KEY']
		)	
		begin
			$stderr.puts "Fetching ElasticIPs in #{thisr} (And associate them with instance Names)"
			fogobj.describe_addresses.body['addressesSet'].each do |eip|
				rhash[ eip['publicIp'] ] = eip['instanceId'] || "UNMAPPED/#{eip['publicIp']}/#{thisr}"
			end
			#Fetch instance Name?
			if instanceinfo
				namehash=Hash.new
				svrs=fogobj.servers({'instance-id' => rhash.values.reject {|i| !i=~/^i-/} })
				svrs.each do |s|
					namehash[s.id]="#{s.tags["Name"]}/#{s.availability_zone}"	
				end	
				rhash.keys.each do |thisi|
					if rhash[thisi]=~/^i-/ && namehash.has_key?(rhash[thisi])
						#puts "#{thisr} : #{thisi} => #{rhash[thisi]} => #{namehash[ rhash[thisi] ]}"
						id=rhash[thisi]
						rhash[thisi]="#{thisi}/#{namehash[id]}"	
					#else
					#	puts "#{thisr} : #{thisi} => #{rhash[thisi]} => NO"	
					end	
				end	
			end		
		rescue Exception => e
			$stderr.puts "Failed to fetch ElasticIPs for region #{thisr} - #{e.inspect}"
		end
		eiphash.merge!(rhash)
	end	
	#puts JSON.pretty_generate(eiphash)
	return eiphash
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
		$stderr.puts "Failed to fetch Elastic Cache security groups! - #{e.inspect}"
		return []
	end
end

def describe_rds_secgroup(region="")
	f=Fog::AWS::RDS.new(
		:region => region,
		:aws_access_key_id => ENV['AWS_ACCESS_KEY_ID'],
		:aws_secret_access_key => ENV['AWS_SECRET_ACCESS_KEY']
	)
	begin
		$stderr.puts "Describing RDS security groups..."
		return f.describe_db_security_groups.body['DescribeDBSecurityGroupsResult']['DBSecurityGroups']
	rescue Exception => e
		abort "Failed to fetch RDS security groups! - #{e.inspect}"
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
cachesec=cli.config[:no_ecache] ? [] : describe_cache_secgroup(THISREGION)
rdssec=cli.config[:no_rds] ? [] : describe_rds_secgroup(THISREGION)


sghash=Hash.new #sg-xxx => sg-description
allsources=Hash.new
cachesecmap=Hash.new #Elastic cache sec groups use lower case description of EC2 sec group name and not its ID :-( So map desc.lowcase -> sg-xxxx
$stderr.puts "*** Not fetching EC2 instance names since --no_meta is true ***" if cli.config[:no_meta]
eipmap=describe_elasticips(cli.config[:allregions], !cli.config[:no_meta])


#First process all EC2 security group info.
ec2sec.each do |thisg|
	tgtgroupdesc=getGroupDesc(thisg)
	sghash[ thisg['groupId' ] ]=tgtgroupdesc
	cachesecmap[ thisg['groupName'].downcase ] = thisg['groupId']	#well, >1 groups could have the same description... :-(
	next unless tgtgroupdesc.match(DstRe)
	thisg['ipPermissions'].each do |this_allowed|
		proto_port_combo=this_allowed['ipProtocol']+":"+this_allowed['toPort'].to_s
		proto_port_combo="ANY" if proto_port_combo=="-1:"
		#The "source" could be either a IP subnet or another security group.
		this_allowed['groups'].each do |x|
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
			srcid=getSubnetDesc(y['cidrIp'],eipmap)
			next unless srcid.match(SrcRe)
			allsources[srcid]={'allowed_into'=>Hash.new} unless allsources.has_key?(srcid)
			allsources[srcid]['allowed_into'][tgtgroupdesc]=[] unless allsources[srcid]['allowed_into'].has_key?(tgtgroupdesc)
			allsources[srcid]['allowed_into'][tgtgroupdesc].push(proto_port_combo)
		end				
	end	
end


#Now process the elastic cache security groups too
cachesec.each do |thiscgrp|
	gname=thiscgrp['CacheSecurityGroupName']
	thiscgrp['EC2SecurityGroups'].each do |ec2grp|
		name=ec2grp['EC2SecurityGroupName']
		id=cachesecmap.has_key?(name) ? cachesecmap[name] : name
		allsources[id]={'allowed_into' => Hash.new} unless allsources.has_key?(id)
		allsources[id]['allowed_into']['CacheGrp:'+gname]=[] unless allsources[id]['allowed_into'].has_key?('CacheGrp:'+gname)
		allsources[id]['allowed_into']['CacheGrp:'+gname].push('cache')	
	end	
end

#Then RDS security groups
rdssec.each do |thisgrp|
	gname=thisgrp['DBSecurityGroupName']
	#Sources could be ec2 sec groups or IP ranges
	thisgrp['EC2SecurityGroups'].each do |eg|
		name=eg['EC2SecurityGroupName']
		id=cachesecmap.has_key?(name) ? cachesecmap[name] : name
		#$stderr.puts "SG #{name} => #{id}"	
		allsources[id]={'allowed_into' => Hash.new} unless allsources.has_key?(id)
		allsources[id]['allowed_into']['RdsGrp:'+gname]=[] unless allsources[id]['allowed_into'].has_key?('RdsGrp:'+gname)
		allsources[id]['allowed_into']['RdsGrp:'+gname].push('rds')		
	end
				
	thisgrp['IPRanges'].each do |ipr|
		id=getSubnetDesc(ipr['CIDRIP'],eipmap)
		#$stderr.puts "IP #{ipr['CIDRIP']} => #{id}"	
		allsources[id]={'allowed_into' => Hash.new} unless allsources.has_key?(id)
		allsources[id]['allowed_into']['RdsGrp:'+gname]=[] unless allsources[id]['allowed_into'].has_key?('RdsGrp:'+gname)
		allsources[id]['allowed_into']['RdsGrp:'+gname].push('rds')			
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
		if srcdesc=~/^(Host|^IP-Subnet|EC2) /
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
			elsif thistgtdesc=~/^RdsGrp:/
				colmap[thistgtdesc]=colors.getNext
				t.attributes << tab + bold + filled
				t.attributes << colmap[thistgtdesc]
			else
				#colmap[thistgtdesc]=send(colors.getNext) unless colmap.has_key?(thistgt)
				colmap[thistgtdesc]=colors.getNext
				t.attributes << colmap[thistgtdesc] 
				t.attributes << filled
			end
			edge(srcdesc, thistgtdesc).label(note).attributes << colmap[srcdesc] #Edge set to same color as SRC
		end		
	end
	
	save cli.config[:filename], cli.config[:format]
end

$stderr.puts "Wrote map to #{cli.config[:filename]}.#{cli.config[:format]}"
