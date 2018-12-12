import json
import pandas as pd

def gen_fjson(filename):
    """
    Iterate over objects in an FJSON file.
    """
    with open(filename) as f:
        for line in f:
            try:
                yield json.loads(line)
            except:
                pass

def rejoin_tfo_df(tfo_rdf, config_column='config'):
    tfo_df = tfo_rdf.loc[:,[config_column,'connstate','dip','host','rank',
                            'fwd_rst','rev_rst','tfo_seq','tfo_ack','tfo_dlen',
                            'tfo_synclen','tfo_synkind','tfo_ackclen','tfo_ackkind']]

    tfo_0df = tfo_df[tfo_df[config_column] == 0]
    tfo_0df.index = tfo_0df.dip
    del(tfo_0df[config_column])
    del(tfo_0df['dip'])
    del(tfo_0df['tfo_seq'])
    del(tfo_0df['tfo_ack'])
    del(tfo_0df['tfo_dlen'])
    del(tfo_0df['tfo_synclen'])
    del(tfo_0df['tfo_synkind'])
    del(tfo_0df['tfo_ackclen'])
    del(tfo_0df['tfo_ackkind'])
    tfo_0df.columns = ['conn_t0','host','rank','fwd_rst_t0','rev_rst_t0']

    tfo_1df = tfo_df[tfo_df[config_column] == 1]
    tfo_1df.index = tfo_1df.dip
    del(tfo_1df[config_column])
    del(tfo_1df['dip'])
    del(tfo_1df['host'])
    del(tfo_1df['rank'])
    tfo_1df.columns = ['conn_t1','fwd_rst_t1','rev_rst_t1','tfo_seq','tfo_ack','tfo_dlen',
                       'tfo_synclen','tfo_synkind','tfo_ackclen','tfo_ackkind']

    tfo_jdf = tfo_0df.join(tfo_1df, how="inner")
    tfo_xdf = tfo_0df.loc[tfo_0df.index.difference(tfo_1df.index)]
    
    return(tfo_jdf, tfo_xdf)
            
import requests
import ipaddress

def canid_prefix_asn(addr):
    res = requests.get("http://localhost:8081/prefix.json?addr="+str(addr))
    j = res.json()
    return {'addr': addr,
            'prefix': j['Prefix'],
            'asn': j['ASN'] }
            

def ripestat_prefix_asn(addr):
    res = requests.get("https://stat.ripe.net/data/prefix-overview/data.json?resource="+str(addr))
    data = res.json()['data']
    prefix = None
    asn = None
    try:
        prefix = data['resource']
        asn = data['asns'][0]['asn']
    except KeyError:
        pass
    return {'addr':   addr,
            'prefix': prefix, 
            'asn':    asn}

def prefix_asn_df(df, prefix_cache):
    
    rows = []
    
    for addr in df.index.values:
        
        naddr = ipaddress.ip_network(addr)
        row = None
        
        # check prefix cache
        for pfx in prefix_cache:
            if pfx.overlaps(naddr):
                # cache hit, exit
                row = prefix_cache[pfx].copy()
                row['addr'] = addr
                #print("cached:   "+repr(row))

        # or go to a local canid cache of ripestat
        if not row:
            row = canid_prefix_asn(addr)
            #print("ripestat: "+repr(row))
            prefix_cache[ipaddress.ip_network(row['prefix'])] = row
        
        rows.append(row)
    
    # now augment the input frame
    odf = pd.DataFrame(rows)
    odf.index = odf['addr']
    del(odf['addr'])
    return df.join(odf)

def select_ip4(df):
    return df.loc[pd.Index((s for s in df.index.values if ':' not in s))]

def select_ip6(df):
    return df.loc[pd.Index((s for s in df.index.values if ':'     in s))]

#resolute_rdf = pd.DataFrame(gen_fjson("tfo-full-resolute-20170116.ndjson"))
#%time (resolute_jdf, resolute_xdf) = rejoin_tfo_df(pd.DataFrame(resolute_rdf))

# Merge two runs, only add missing rows from second
#%time (tfo_a_jdf, tfo_a_xdf) = rejoin_tfo_df(pd.DataFrame(gen_fjson("1m-run4.fjson")))
#%time (tfo_b_jdf, tfo_b_xdf) = rejoin_tfo_df(pd.DataFrame(gen_fjson("1m-run4b.fjson")))

#tfo_jdf = tfo_a_jdf.append(tfo_b_jdf).reset_index().drop_duplicates(subset='dip', keep='first').set_index('dip')
#tfo_xdf = tfo_a_xdf.append(tfo_b_xdf).reset_index().drop_duplicates(subset='dip', keep='first').set_index('dip')

(tfo6_jdf, tfo6_xdf) = rejoin_tfo_df(pd.DataFrame(gen_fjson("/data/mami/raw/mustgofaster-tfo/fjson-bz2/1m-run6.fjson")),config_column='tfostate')

def tfo_sieve(tfo_jdf, tfo_xdf, prefix_cache):
    # Cookie available on SYN, but not ACK
    tfo_rscookie = tfo_jdf[(tfo_jdf['tfo_synclen'] > 0) & (tfo_jdf['tfo_ackclen'] == 0)]
    
    # Cookie available on ACK, but not SYN (probably retry 254)
    tfo_racookie = tfo_jdf[(tfo_jdf['tfo_synclen'] == 0) & (tfo_jdf['tfo_ackclen'] > 0)]

    # Cookie available on ACK, but not SYN (probably retry 254)
    tfo_rascookie = tfo_jdf[(tfo_jdf['tfo_synclen'] > 0) & (tfo_jdf['tfo_ackclen'] > 0)]

    # Add ASN information to cookie table, we'll use it later
    tfo_cookie = prefix_asn_df(tfo_rscookie.append(tfo_racookie).append(tfo_rascookie), prefix_cache)

    # (special cases... SYN cookie, but not eight bytes long)
    tfo_oddcookie = tfo_cookie[(tfo_cookie['tfo_synclen'] > 0) & (tfo_cookie['tfo_synclen'] != 8)]

    # (special cases... ACK cookie of kind 254: retry)
    tfo_expcookie = tfo_cookie[(tfo_cookie['tfo_ackclen'] > 0) & (tfo_cookie['tfo_ackkind'] == 254)]

    # (special cases... ACK cookie even with SYN cookie)
    tfo_twocookie = tfo_cookie[(tfo_cookie['tfo_synclen'] > 0) & (tfo_cookie['tfo_ackclen'] > 0)]
    
    # TFO works: data sent and ACKed
    tfo_works = tfo_cookie[((tfo_cookie['tfo_ack'] - tfo_cookie['tfo_seq'] - 1) == tfo_cookie['tfo_dlen'])]

    # TFO data not acked: data sent, but ACK only ACKs SYN
    tfo_dna = tfo_cookie[((tfo_cookie['tfo_ack'] - tfo_cookie['tfo_seq'] - 1) == 0)]

    # TFO data failed: data seen, but no ACK seen
    tfo_dfail = tfo_cookie[tfo_cookie['tfo_ack'] == 0]

    # No cookie available
    tfo_nocookie = tfo_jdf[tfo_jdf['tfo_synclen'] == 0]

    # TFO connection failures (where TFO attempted)
    tfo_cfail = tfo_nocookie[~tfo_nocookie['conn_t1']]

    # TFO not negotiated
    tfo_nope = tfo_nocookie[tfo_nocookie['conn_t1']]

    # Complete connection failures
    total_cfail = tfo_xdf[~tfo_xdf['conn_t0']]

    # TFO connection failures (either TFO not attempted or not seen)
    xtfo_cfail = tfo_xdf[tfo_xdf['conn_t0']]
    
    # summarize
    ct_total = len(tfo_jdf) + len(tfo_xdf)
    ct_totalfail = len(total_cfail)
    ct_tfocfail = len(tfo_cfail) + len(xtfo_cfail)
    ct_tfonope = len(tfo_nope)

    ct_tfodfail = len(tfo_dfail)
    ct_tfodna = len(tfo_dna)
    ct_tfoworks = len(tfo_works)
    ct_tfonego = len(tfo_cookie)

    ct_oddcookie = len(tfo_oddcookie)
    ct_expcookie = len(tfo_expcookie)
    ct_twocookie = len(tfo_twocookie)

    ct_tfogoog = len(tfo_cookie[tfo_cookie['asn'] == 15169])
    ct_tfongoog = len(tfo_cookie[tfo_cookie['asn'] != 15169])

    print("Of %6u tested IP addresses:" % (ct_total,))
    print("   %6u (%6.3f%%) completely failed to connect." % (ct_totalfail, 100 * ct_totalfail / ct_total))
    print("   %6u (%6.3f%%) may have TFO-dependent failure." % (ct_tfocfail, 100 * ct_tfocfail / ct_total))
    print("   %6u (%6.3f%%) did not negotiate TFO." % (ct_tfonope, 100 * ct_tfonope / ct_total))
    print("   %6u (%6.3f%%) negotiated TFO, of which:" % (ct_tfonego, 100 * ct_tfonego / ct_total))
    print(" - - - - - - - -")
    print("   %6u (%6.3f%% / %6.3f%%) responded with a type-254 cookie" % 
                  (ct_expcookie, 100 * ct_expcookie / ct_tfonego, 100 * ct_expcookie / ct_total))
    print("   %6u (%6.3f%% / %6.3f%%) responded with a non-8-byte cookie" % 
                  (ct_oddcookie, 100 * ct_oddcookie / ct_tfonego, 100 * ct_oddcookie / ct_total))
    print("   %6u (%6.3f%% / %6.3f%%) properly ACKed data on SYN" % 
                  (ct_tfoworks, 100 * ct_tfoworks / ct_tfonego, 100 * ct_tfoworks / ct_total))
    print("   %6u (%6.3f%% / %6.3f%%) returned a cookie while ACKing data on SYN" % 
                  (ct_twocookie, 100 * ct_twocookie / ct_tfonego, 100 * ct_twocookie / ct_total))
    print("   %6u (%6.3f%% / %6.3f%%) did not ACK data on SYN" % 
                  (ct_tfodna, 100 * ct_tfodna / ct_tfonego, 100 * ct_tfodna / ct_total))
    print("   %6u (%6.3f%% / %6.3f%%) failed with data on SYN" % 
                  (ct_tfodfail, 100 * ct_tfodfail / ct_tfonego, 100 * ct_tfodfail / ct_total))
    print(" - - - - - - - -")
    print("   %6u (%6.3f%% / %6.3f%%) are Google properties" %
                  (ct_tfogoog, 100 * ct_tfogoog / ct_tfonego, 100 * ct_tfogoog / ct_total))
    print("   %6u (%6.3f%% / %6.3f%%) are not Google properties" %
                  (ct_tfongoog, 100 * ct_tfongoog / ct_tfonego, 100 * ct_tfongoog / ct_total))

    return {'cookie': tfo_cookie,
            'oddcookie': tfo_oddcookie,
            'expcookie': tfo_expcookie,
            'twocookie': tfo_twocookie,
            'works': tfo_works,
            'dna': tfo_dna,
            'dfail': tfo_dfail,
            'nope': tfo_nope,
            'tcfail': total_cfail,
            'xcfail': xtfo_cfail}


    
if __name__ == '__main__':
    prefix_cache = {}
    print('All addresses:')
    sieve6all = tfo_sieve(tfo6_jdf, tfo6_xdf, prefix_cache)
    
    print('IPv4 only:')
    sieve6v4 = tfo_sieve(select_ip4(tfo6_jdf), select_ip4(tfo6_xdf), prefix_cache)
    
    print('IPv6 only:')
    sieve6v6 = tfo_sieve(select_ip6(tfo6_jdf), select_ip6(tfo6_xdf), prefix_cache)
    
    sieve6all['oddcookie']
    sieve6all['expcookie']
    sieve6all['twocookie']
