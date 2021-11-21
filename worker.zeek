@load base/protocols/conn
@load base/protocols/ssh
@load packages/zeek-kafka
@load ./traffic_log

module Worker;

event zeek_init()
    {
    if ( Supervisor::is_supervisor() )
        {
        Broker::peer(getenv("MANAGER_IP"), to_port(getenv("BROKER_PORT") + "/tcp"));

        local cluster: table[string] of Supervisor::ClusterEndpoint;
        cluster["manager"] = [
            $role=Supervisor::MANAGER,
            $host=to_addr(getenv("MANAGER_IP")),
            $p=10001/tcp
        ];
        cluster["worker"] = [
            $role=Supervisor::WORKER,
            $host=127.0.0.1,
            $p=10000/tcp,
            $interface=getenv("CAPTURE_INTERFACE")
        ];
        
        for ( n, ep in cluster )
            {
            local sn = Supervisor::NodeConfig($name=n);
            sn$cluster = cluster;
            sn$directory = n;

            if ( ep?$interface )
                sn$interface = ep$interface;

            local res = Supervisor::create(sn);

            if ( res != "" )
                print fmt("supervisor failed to create node '%s': %s", n, res);
            }
        }
    else
        print fmt("supervised node '%s' zeek_init()", Supervisor::node()$name);
        Log::create_stream(TrafficLog::LOG, [$columns=TrafficLog::Info, $ev=TrafficLog::log_test, $path="factor"]);
    }

event connection_state_remove(c: connection)
    {
    local orig = 0;
    local resp = 0;
    local land = 0;
    local logged_in = 0;

    print fmt("packet received.");
    print fmt("missed bytes: %s, wrong fragment: %s", c$conn$missed_bytes, c$conn$missed_bytes/1500);

    if ( c$conn?$orig_bytes )
        orig = c$conn$orig_bytes;
    if ( c$conn?$resp_bytes )
        resp = c$conn$resp_bytes;
    if ( c$id$orig_h == c$id$resp_h && c$id$orig_p == c$id$resp_p )
        land = 1;
    # if ( c$ssh$auth_success )
    #     logged_in = 1;

    local log: TrafficLog::Info = [
        $duration=interval_to_double(c$duration),
        $service=c$service,
        $protocol_type=cat(c$conn$proto),
        $flag=+0,
        $source_bytes=orig,
        $destination_bytes=resp,
        $land=land,
        $wrong_fragment=c$conn$missed_bytes/1500
        # $num_failed_logins=c$ssh$auth_attempts,
        # $logged_in=logged_in
    ];

    Broker::publish("zeek/logs/forward/test", TrafficLog::log_test, log);
    }

event ssh_auth_attempted(c: connection, authenticated: bool)
    {
    print fmt("ssh_auth_attempted: ", c);
    }

event zeek_done()
    {
    if ( Supervisor::is_supervised() )
        print fmt("supervised node '%s' zeek_done()", Supervisor::node()$name);
    else
        print "supervisor zeek_done()";
    }