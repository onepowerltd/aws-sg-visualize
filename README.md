Visualize AWS Security groups for a region
==========================================

A picture is worth a thousand words right? This lets you build a SVG of the EC2, RDS and Elastic Cache security groups in a given EC2 region.

1. Runs describe-security groups against specified regions EC2, RDS and Elastic Cache.
2. Based on the described groups, builds a sources hash and converts them to a directional graph (always `Source` to `Destination`).
3. Renders the graph as SVG/PNG via [the very awesome Graphviz](http://www.graphviz.org/)
4. For a bit of high level overview without having to read through it all, Hosts/IP blocks as diamonds, RDS groups as parallelograms and Elastic Cache groups as trapeziums.
5. If you leave `--no_meta` at default (`false`), then this will also poll all EC2 elastic IP addresses (in all regions specified as `--allregions r1,r2,r3..`) and "convert" them to something like `EC2 <eip>/<nodes name tag>/<AZ>` etc.
6. Any EC2 IP thats not allocated to an instance will show up with text `UNMAPPED`.
7. If you would like to attach descriptions for static IP addresses / subnets (e.g. your corporate network) to the PNG/SVG, then edit/create `~/.aws-sg-visualize/hostmap` and add one line for each e.g. like this:

```

[smohan@Srinivasans-MacBook-Pro-3 aws-sg-visualize]$ cat ~/.aws-sg-visualize/hostmap
#My rackspace host
1.2.3.4 rspace1
#Work/office subnet
5.6.7.0/24 CorpNetwork1

```

** Any IP addresses defined in `~/.aws-sg-visualize/hostmap` will override information fetched from EC2 (describe elastic IP addresses) **

Here is a sample (albeit with very few groups - Not gonna post a real accounts 'network diagram' in here :-))

![Alt text](/demo.png "Sample SVG")

Prerequisites
=============

Need graphviz installed.

On OSX -

```
brew install graphviz

```

On Ubuntu -

```

apt-get install graphviz


```

An Amazon EC2 account with admin privileges and API keys setup. These will need to be available as `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` for script to run.

You will also need the Ruby Gems `fog`, `graph` and `mixlib-cli` - The `bundle install` should take care of those for you.

Install
=======


Clone from this repo and run `bundle install` to install the required gems (Namely fog and graph)

```

git clone git@github.com:onepowerltd/aws-sg-visualize.git
cd aws-sg-visualize
bundle install

```

How to run
==========

Make sure you have the AWS key id and secret key set. e.g.

```
export AWS_ACCESS_KEY_ID="somekeyid"
export AWS_SECRET_ACCESS_KEY="somesecret"

```

The simplest run is `./buildSecGroupMap.rb` - This defaults to building a SVG (/tmp/sgmap.svg) for AWS region `us-west-2`.

You can always filter by source/dest IP/group names/descriptions etc and dump the generated JSON (from `ec2-describe-groups` call) etc. Other command line options are:

```

[smohan@Srinivasans-MacBook-Pro-3 aws-sg-visualize]$ ./buildSecGroupMap.rb -h
Usage: ./buildSecGroupMap.rb (options)
        --allregions us-west-1,us-east-1
                                     Comma separated list of AWS regions you want to poll for elastic IP mappings
    -d, --dest DEST                  Regexp to filter results to match by Destination Group name. Default is to match all.
    -f, --filename FILENAME          Filename (no svg/png suffix) to dump map into. Defaults to /tmp/sgmap(.svg)
    -m, --mode FORMAT                svg/png only - For generated graph. Defaults to svg
    -h, --help                       Show this Help message.
    -j, --json                       Dump the JSON from which SVG/PNG is built
        --ecache-disable             Set to disable describing Elastic Cache security groups
        --no_meta                    Disables EC2 instance meta-data fetch (To resolve elastic IPs to ec2 host). Defaults to false
        --rds-disable                Set to disable describing RDS security groups
    -n, --nograph                    Disable PNG/SVG object generation. False by default.
    -r, --region REGION              AWS Region for which to describe Security groups. Defaults to us-west-2
    -s, --source SOURCE              Regexp to filter results to match by Source IP/Groups/Groupname. Default is to match all.

```


Known Issues
============

* Colors chosen are not perfect - Not exactly eye-candy :-)
* As mentioned in [Issue 1](https://github.com/onepowerltd/aws-sg-visualize/issues/1), describing VPC elastic-cache groups throws an error. Will get to it soon. Works fine in classic EC2.
