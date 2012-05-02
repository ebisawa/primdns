require 'unittest.rb'

test 'Query domain name in delegated zone (1)' do
  query 'x.sub1.example.com' do
    assert_status 'NOERROR'
    assert_flags 'qr', '!aa'
    assert_noanswer
    assert_authority 'ns1.sub1.example.com'
    assert_authority 'ns2.sub1.example.com'
    assert_noadditional
  end
end

test 'Query domain name in delegated zone (2)' do
  query 'x.sub2.example.com' do
    assert_status 'NOERROR'
    assert_flags 'qr', '!aa'
    assert_noanswer
    assert_authority 'ns1.sub2.example.com'
    assert_authority 'ns2.sub2.example.com'

    assert_additional '192.0.2.11', 'ns1.sub2.example.com'
    assert_additional '192.0.2.12', 'ns2.sub2.example.com'
    assert_additional '2001:db8::2:11', 'ns1.sub2.example.com'
    assert_additional '2001:db8::2:12', 'ns2.sub2.example.com'
  end
end

test 'Query domain name in delegated zone (3)' do
  query 'x.sub3.example.com' do
    assert_status 'NOERROR'
    assert_flags 'qr', '!aa'
    assert_noanswer
    assert_authority 'ns1.example.net'
    assert_authority 'ns2.example.net'

    assert_additional '192.0.2.100', 'ns1.example.net'
    assert_additional '192.0.2.101', 'ns2.example.net'
  end
end

test 'Query domain name in delegated zone (4)' do
  query 'x.sub4.example.com' do
    assert_status 'NXDOMAIN'
    assert_flags 'qr', 'aa'
    assert_noanswer
    assert_authority_type 'SOA'
    assert_noadditional
  end
end

test 'Query domain name in delegated zone (5)' do
  query 'a.sub4.example.com' do
    assert_status 'NOERROR'
    assert_flags 'qr', 'aa'
    assert_answer '192.0.2.44'
    assert_authority 'ns1.sub4.example.com'
    assert_authority 'ns2.sub4.example.com'
    assert_authority 'ns3.sub4.example.com'

    assert_additional '192.0.2.41', 'ns1.sub4.example.com'
    assert_additional '192.0.2.42', 'ns2.sub4.example.com'
    assert_additional '192.0.2.43', 'ns3.sub4.example.com'
  end
end

test 'Query referral itsself' do
  query 'NS sub2.example.com' do
    assert_status 'NOERROR'
    assert_flags 'qr', '!aa'
    assert_noanswer
    assert_authority 'ns1.sub2.example.com'
    assert_authority 'ns2.sub2.example.com'

    assert_additional '192.0.2.11', 'ns1.sub2.example.com'
    assert_additional '192.0.2.12', 'ns2.sub2.example.com'
    assert_additional '2001:db8::2:11', 'ns1.sub2.example.com'
    assert_additional '2001:db8::2:12', 'ns2.sub2.example.com'
  end
end

test 'Query CNAME to referral' do
  query 'NS b.example.com' do
    assert_status 'NOERROR'
    assert_flags 'qr', 'aa'
    assert_answer 'sub2.example.com', 'CNAME'
    assert_authority 'ns1.sub2.example.com'
    assert_authority 'ns2.sub2.example.com'

    assert_additional '192.0.2.11', 'ns1.sub2.example.com'
    assert_additional '192.0.2.12', 'ns2.sub2.example.com'
    assert_additional '2001:db8::2:11', 'ns1.sub2.example.com'
    assert_additional '2001:db8::2:12', 'ns2.sub2.example.com'
  end
end

test 'Query CNAME to zone NS' do
  query 'NS c.example.com' do
    assert_status 'NOERROR'
    assert_flags 'qr', 'aa'
    assert_answer 'example.com', 'CNAME'
    assert_answer 'ns1.example.com', 'NS'
    assert_answer 'ns2.example.com', 'NS'
    assert_noauthority

    assert_additional '192.0.2.1', 'ns1.example.com'
    assert_additional '192.0.2.2', 'ns2.example.com'
    assert_additional '2001:db8::2:2', 'ns2.example.com'
  end
end
