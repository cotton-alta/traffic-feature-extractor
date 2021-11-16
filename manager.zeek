@load base/protocols/conn
@load packages/zeek-kafka
@load ./traffic_log

module Manager;

event zeek_init()
    {
    if ( Supervisor::is_supervisor() )
        {
        Broker::subscribe("zeek/logs");
		Broker::listen("127.0.0.1", to_port(getenv("BROKER_PORT") + "/tcp"));

        local cluster: table[string] of Supervisor::ClusterEndpoint;
        cluster["manager"] = [
            $role=Supervisor::MANAGER,
            $host=127.0.0.1,
            $p=10001/tcp
        ];
        cluster["worker"] = [
            $role=Supervisor::WORKER,
            $host=to_addr(getenv("WORKER_IP")),
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

event zeek_done()
    {
    if ( Supervisor::is_supervised() )
        print fmt("supervised node '%s' zeek_done()", Supervisor::node()$name);
    else
        print "supervisor zeek_done()";
    }