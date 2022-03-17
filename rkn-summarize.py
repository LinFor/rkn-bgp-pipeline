#!/usr/bin/python3

import itertools, ipaddress as ipa

min_replacement_factor = 0.7

real_counts = {}

prom_stats_extracted_address_count = None
prom_stats_exported_covered_address_real_count = None
prom_stats_exported_covered_address_fake_count = None
prom_stats_exported_routes_count = None

def safe_list_get(l, idx, default):
  try:
    return l[idx]
  except IndexError:
    return default

def load_ips(filename):
    infile = open(filename, 'r')
    trimmed = map(lambda r: r.rstrip(), infile)
    without_blanks = filter(lambda r: r, trimmed)
    ips = map(lambda r: ipa.IPv4Network(r), without_blanks)
    return ips

def init_real_counts(ips):
    global real_counts
    real_counts.clear()
    for ip in ips:
        bucket = real_counts.setdefault(ip.prefixlen, {})
        bucket[ip] = ip.num_addresses

def remove_real_inners(ip):
    if ip.num_addresses < 2:
        return
    global real_counts
    bucket = real_counts.setdefault(ip.prefixlen + 1, {})
    for subnet in ip.subnets():
        bucket.pop(subnet, None)
        remove_real_inners(subnet)

def _update_real_counts(ip, real):
    global real_counts
    bucket = real_counts.setdefault(ip.prefixlen, {})
    bucket[ip] = real
    remove_real_inners(ip)
    return real

def update_real_counts(ip):
    real = calculate_real_stats_by_net(ip)
    return _update_real_counts(ip, real)

def calculate_real_stats_both_sides(ip):
    subnets = list(ip.subnets())
    side0 = calculate_real_stats_by_net(subnets[0])
    side1 = calculate_real_stats_by_net(subnets[1])
    return side0, side1

def calculate_real_stats_by_net(ip):
    global real_counts
    bucket = real_counts.setdefault(ip.prefixlen, {})
    real = bucket.get(ip, None)
    if real:
        return real
    elif ip.num_addresses == 1:
        return 0
    else:
        real = 0
        for subnet in ip.subnets():
            real += calculate_real_stats_by_net(subnet)
        if real == 0 and ip.num_addresses > 1 and ip.prefixlen % 4 == 0:
            _update_real_counts(ip, real)
        return real

def calculate_real_fake_stats(ips):
    real = 0
    fake = 0
    for ip in ips:
        ip_real = calculate_real_stats_by_net(ip)
        real += ip_real
        fake += ip.num_addresses - ip_real
    return real, fake

def _get_ips():
    global real_counts
    res = []
    for prefixlen in sorted(real_counts.keys()):
        bucket = real_counts.get(prefixlen)
        for ip in bucket.keys():
            if bucket.get(ip, 0) > 0:
                res.append(ip)
    return res

def output_routes(filename):
    global real_counts
    total_count = 0
    total_real = 0
    total_addresses = 0
    with open(filename, 'w') as outfile:
        for prefixlen in sorted(real_counts.keys()):
            bucket = real_counts.get(prefixlen)
            for ip in bucket.keys():
                real = bucket.get(ip, 0)
                if real > 0:
                    outfile.write(f"route {ip} unreachable;")
                    if ip.num_addresses > 1:
                        outfile.write(f" # {real} / {ip.num_addresses} ({real * 100 / ip.num_addresses:.2f}%)")
                    outfile.write("\n")
                    total_count += 1
                    total_real += real
                    total_addresses += ip.num_addresses

    global prom_stats_exported_routes_count
    global prom_stats_exported_covered_address_real_count
    global prom_stats_exported_covered_address_fake_count
    prom_stats_exported_routes_count = total_count
    prom_stats_exported_covered_address_real_count = total_real
    prom_stats_exported_covered_address_fake_count = total_addresses - total_real
    print(f"Output {total_count} routes, {total_real} / {total_addresses} ({total_real * 100 / total_addresses:.2f}%).")

def output_prometheus(filename):
    with open(filename, 'w') as outfile:
        outfile.write("# HELP rkn_bypass_extracted_address_total Total number of IPv4 addresses extracted from RKN dumps.\n")
        outfile.write("# TYPE rkn_bypass_extracted_address_total gauge\n")
        outfile.write(f"rkn_bypass_extracted_address_total {prom_stats_extracted_address_count}\n")

        outfile.write("# HELP rkn_bypass_exported_routes_total Total number of summarized routes exported.\n")
        outfile.write("# TYPE rkn_bypass_exported_routes_total gauge\n")
        outfile.write(f"rkn_bypass_exported_routes_total {prom_stats_exported_routes_count}\n")

        outfile.write("# HELP rkn_bypass_exported_covered_address_total Number of covered addresses by kind.\n")
        outfile.write("# TYPE rkn_bypass_exported_covered_address_total gauge\n")
        outfile.write(f"rkn_bypass_exported_covered_address_total{{kind=\"real\"}} {prom_stats_exported_covered_address_real_count}\n")
        outfile.write(f"rkn_bypass_exported_covered_address_total{{kind=\"fake\"}} {prom_stats_exported_covered_address_fake_count}\n")

def print_bucket_stats():
    global real_counts
    for prefixlen in sorted(real_counts.keys()):
        bucket = real_counts.get(prefixlen)
        print(f"Bucket #{prefixlen}, {len(bucket)} nets in bucket")


def summarize_level(prefixlen):
    global real_counts
    print(f"Pass {prefixlen} starting...")
    lower_bucket = real_counts.setdefault(prefixlen + 1, {})
    current_bucket = real_counts.setdefault(prefixlen, {})
    lower_bucket_ips = sorted(lower_bucket.keys())
    for ip in lower_bucket_ips:
        if lower_bucket.get(ip, 0) < 1:
            continue
        super = ip.supernet()
        if current_bucket.get(super, None):
            continue
        real0, real1 = calculate_real_stats_both_sides(super)
        real = real0 + real1
        if real0 > 0 and real1 > 0 and real / super.num_addresses >= min_replacement_factor:
            _update_real_counts(super, real)
    print(f"Pass {prefixlen} complete.")

def summarize():
    current_prefixlen = 31
    while current_prefixlen > 0:
        summarize_level(current_prefixlen)

        # print_bucket_stats()

        current_prefixlen -= 1


# ips_iter = load_ips('testdata')
ips_iter = load_ips('.v4.addr')
# subset = ipa.IPv4Network('0.0.0.0/4')
# ips_iter = filter(lambda ip: subset.supernet_of(ip), ips_iter)
ips = list(ips_iter)
prom_stats_extracted_address_count = len(ips)
print(f"Subset of {prom_stats_extracted_address_count} records loaded")

# Unique and ordered
ips = sorted(list(dict.fromkeys(ips)))

init_real_counts(ips)
del ips

summarize()

output_routes('.ips.routes')
output_prometheus('.stats.prom')
