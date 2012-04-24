title 'Query nonexistent zone'

query 'zone.nonexistent'

assert_status 'SERVFAIL'
assert_flag 'qr'
