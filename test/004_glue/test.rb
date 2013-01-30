require 'unittest.rb'

test 'Query domain name in delegated zone' do
  query 'x.sub1.example.com' do
    assert_status 'NOERROR'
    assert_flags 'qr', '!aa'
    assert_noanswer
    assert_authority 'ns1.example.net'
    assert_authority 'ns2.sub1.example.com'
    assert_additional '192.0.2.11'
    assert_additional '2001:db8::11'
    assert_additional '192.0.2.12'
  end
end

test 'Query glue A (1)' do
  query 'ns1.example.net' do
    assert_status 'SERVFAIL'
    assert_flags 'qr', '!aa'
    assert_noanswer
    assert_noauthority
    assert_noadditional
  end
end

test 'Query glue A (2)' do
  query 'ns2.sub1.example.com' do
    assert_status 'NOERROR'
    assert_flags 'qr', '!aa'
    assert_noanswer
  end
end
