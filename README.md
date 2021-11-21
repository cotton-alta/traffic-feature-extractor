# traffic-feature-extractor
Extracting Traffic Features with Zeek

## setup
1. Create a docker image.
```
$ docker build --build-arg ZEEK_VERSION=4.0.1 --build-arg LIBRDKAFKA_VERSION=1.4.2 -t traffic-feature-extractor .
```

2. Check that the plugin is installed in the container.
```
$ docker run --rm -it traffic-feature-extractor /bin/bash
$ zeek -N Seiso::Kafka
```

3. Run a script to capture traffic.

for mac
```
$ docker run --add-host=localhost:<host private address> -e CAPTURE_INTERFACE=<network interface to capture> -e CAPTURE_PORT=<port on which kafka broker is running> --rm -it traffic-feature-extractor /bin/bash

zeek -j -C extractor.zeek
```

for linux
```
$ docker run --net=host -e CAPTURE_INTERFACE=<network interface to capture> -e CAPTURE_PORT=<port on which kafka broker is running> --rm -it traffic-feature-extractor /bin/bash

zeek -j -C extractor.zeek
```