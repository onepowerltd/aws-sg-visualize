Visualize AWS Security groups for a region
==========================================




Prerequisites
=============

Need graphviz installed.

```

brew install graphviz

```

Install
=======


Clone from this repo and run `bundle install` to install the required gems (Namely fog and graph)

```

git clone XXX
cd xxx
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
    -n, --nograph                    Disable PNG/SVG object generation. False by default.
    -r, --region REGION              AWS Region for which to describe Security groups
    -s, --source SOURCE              Regexp to filter results to match by Source IP/Groups/Groupname. Default is to match all.


```
