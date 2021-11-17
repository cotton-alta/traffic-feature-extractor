module TrafficLog;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        duration:               double &log;
        protocol_type:          string &log;
        service:                set[string] &log;
        flag:                   int &log;
        source_bytes:           count &log;
        destination_bytes:      count &log;
        land:                   int &log;
    };

    redef Kafka::logs_to_send = set(TrafficLog::LOG);
    redef Kafka::topic_name = "zeek";
    redef Kafka::kafka_conf = table(
        ["metadata.broker.list"] = "localhost:" + getenv("CAPTURE_PORT")
    );

    global log_test: event(rec: TrafficLog::Info);
}

event log_test(rec: TrafficLog::Info) 
    {
        print fmt("packet received from worker.");

        Log::write(TrafficLog::LOG, rec);
    }