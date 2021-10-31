# traffic-feature-extractor
Extracting Traffic Features with Zeek

# setup
```
$ docker build --build-arg ZEEK_VERSION=4.0.1 --build-arg LIBRDKAFKA_VERSION=1.4.2 -t traffic-feature-extractor .
$ docker run --rm -it traffic-feature-extractor /bin/bash
```

```
$ zeek -N Seiso::Kafka
```