title 'Simple CNAME Query'

query 'a.example.com'

assert_status 'NOERROR'
assert_flag 'qr'
assert_flag 'aa'
assert_answer 'b.example.com', 'CNAME'
assert_answer '192.0.2.10'
assert_authority 'ns1.example.com'
assert_authority 'ns2.example.com'
