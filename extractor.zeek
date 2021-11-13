@load base/protocols/conn
@load packages/zeek-kafka

module Main;

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

    redef Kafka::logs_to_send = set(Main::LOG);
    redef Kafka::topic_name = "zeek";
    redef Kafka::kafka_conf = table(
        ["metadata.broker.list"] = "localhost:" + getenv("CAPTURE_PORT")
    );
}

event zeek_init()
    {
    if ( Supervisor::is_supervisor() )
        {
        local sn = Supervisor::NodeConfig(
            $name="node1",
            $interface=getenv("CAPTURE_INTERFACE"),
            $directory="./logs"
        );
        local res = Supervisor::create(sn);

        if ( res == "" )
            print "supervisor created a new node";
        else
            print "supervisor failed to create node", res;
        }
    else
        print fmt("supervised node '%s' zeek_init()", Supervisor::node()$name);
        Log::create_stream(LOG, [$columns=Info, $path="factor"]);
    }

event connection_state_remove(c: connection)
    {
    local orig = 0;
    local resp = 0;
    local land = 0;

    if ( c$conn?$orig_bytes )
        orig = c$conn$orig_bytes;
    if ( c$conn?$resp_bytes )
        resp = c$conn$resp_bytes;
    if ( c$id$orig_h == c$id$resp_h && c$id$orig_p == c$id$resp_p )
        land = 1;

    Log::write(Main::LOG, [
        $duration=interval_to_double(c$duration),
        $service=c$service,
        $protocol_type=cat(c$conn$proto),
        $flag=+0,
        $source_bytes=orig,
        $destination_bytes=resp,
        $land=land
    ]);
    }

event zeek_done()
    {
    if ( Supervisor::is_supervised() )
        print fmt("supervised node '%s' zeek_done()", Supervisor::node()$name);
    else
        print "supervisor zeek_done()";
    }