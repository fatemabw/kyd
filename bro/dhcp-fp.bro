@load ./dhcp-db.bro
@load base/protocols/dhcp

module DHCPFP;

export {

    # Append the value LOG to the Log::ID enumerable.
    redef enum Log::ID += { LOG };

    # Define a new type called TLSFP::Info.
    type Info: record {
        ts: time &log;
        conn_uid: string &log;
        c_id: conn_id &log;
        c_history: string &log;
        DHCPclient: string &log;
        DHCPhash: string &log;
        param_list: string &log;
        };
}

type DHCPFPStorage: record {

        DHCPhash: string &default="";
        DHCPclient: string &default="";
        param_list: string &default="";
};

redef record connection += {
        dhcpfp: DHCPFPStorage &optional;
};

@ifdef ( zeek_init )
event zeek_init()
@else
event bro_init()
@endif
    {
    # Create the logging stream.
    Log::create_stream(LOG, [$columns=Info, $path="dhcpfp"]);
    }

event dhcp_message(c: connection, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options) &priority=5

{       if ( msg$op !=1)
                return;

        if (!c?$dhcpfp )
        {
                c$dhcpfp=DHCPFPStorage();

                local s1 : string ="";
                local s2 : string ="";
                local s3 : string ="";

                if( options?$param_list && |options$param_list|>0)
                {
                        local h = md5_hash_init();

                        s1 = sub(cat(options$param_list),/\[/,"");
                        s2 = sub(s1,/\]/,"");
                        s3 = subst_string(s2," ","");
                        md5_hash_update(h, s3);
                        local hash = md5_hash_finish(h);

                        c$dhcpfp$param_list = s3;
                        c$dhcpfp$DHCPhash = hash;

                        if ( hash in DHCPFingerprinting::database )
                        {
                                c$dhcpfp$DHCPclient = DHCPFingerprinting::database[hash];
                        }
                        else
                        {
                                c$dhcpfp$DHCPclient = "Unknown";
                        }
                        local rec: DHCPFP::Info = [ $ts=c$start_time, $conn_uid=c$uid, $c_id=c$id , $c_history=c$history, $DHCPclient=c$dhcpfp$DHCPclient, $DHCPhash=c$dhcpfp$DHCPhash, $param_list = c$dhcpfp$param_list];
                        Log::write( DHCPFP::LOG, rec);
                }
        }
}
