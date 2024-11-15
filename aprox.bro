#event bro_init()
#    {
#    local addr_vector: vector of addr = vector(1.2.3.4, 2.3.4.5, 3.4.5.6);

#    for (i in addr_vector)
#        print mask_addr(addr_vector[i], 18);
#    }

# Store the time the previous connection was established.
global last_connection_time: time;

# boolean value to indicate whether we have seen a previous connection.
global connection_seen: bool = F;

event connection_established(c: connection)
    {
    local net_time: time  = network_time();

    print fmt("%s:  New connection established from %s to %s", strftime("%Y/%M/%d %H:%m:%S", net_time), c$id$orig_h, c$id$resp_h);

    if ( connection_seen )
        print fmt("     Time since last connection: %s", net_time - last_connection_time);

    last_connection_time = net_time;
    connection_seen = T;
    }
