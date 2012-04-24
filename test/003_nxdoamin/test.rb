title 'Query nonexistent domain name'

query 'nonexistent.example.com'

assert_status 'NXDOMAIN'
assert_flag 'qr'
assert_flag 'aa'
assert_authority_type 'SOA'
