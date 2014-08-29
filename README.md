Visualize AWS Security groups for a region
==========================================

A picture is worth a thousand words right? This lets you build a SVG of the EC2, RDS and Elastic Cache security groups in a given EC2 region.

1. Runs describe-security groups against specified regions EC2, RDS and Elastic Cache.
2. Based on the described groups, builds a sources hash and converts them to a directional graph (always `Source` to `Destination`).
3. Renders the graph as SVG/PNG via [the very awesome Graphviz](http://www.graphviz.org/)
4. For a bit of high level overview without having to read through it all, Hosts/IP blocks as diamonds, RDS groups as parallelograms and Elastic Cache groups as trapeziums.

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

You will also need the Ruby Gems `fog`, `graph` and `mizlib-cli` - The `bundle install` should take care of those for you.

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

[smohan@Srinivasans-MacBook-Pro aws-sg-visualize]$ ./buildSecGroupMap.rb -h
Usage: ./buildSecGroupMap.rb (options)
    -d, --dest DEST                  Regexp to filter results to match by Destination SecGroup. Default is to match all.
    -f, --filename FILENAME          Filename (no svg/png suffix) to dump map into. Defaults to /tmp/sgmap(.svg)
    -m, --mode FORMAT                svg/png only - For generated graph. Defaults to svg
    -h, --help                       Show this Help message.
    -j, --json                       Dump the JSON from which SVG/PNG is built
        --ecache-disable             Set to disable describing Elastic Cache security groups
        --rds-disable                Set to disable describing RDS security groups
    -n, --nograph                    Disable PNG/SVG object generation. False by default.
    -r, --region REGION              AWS Region for which to describe Security groups
    -s, --source SOURCE              Regexp to filter results to match by Source IP/Groups/Groupname. Default is to match all.

```


Known Issues
============

* Colors chosen are not perfect - Not exactly eye-candy :-)
* As mentioned in [Issue 1](https://github.com/onepowerltd/aws-sg-visualize/issues/1), describing VPC elastic-cache groups throws an error. Will get to it soon. Works fine in classic EC2.
