require 'unittest.rb'

test 'Simple query' do
  query 'a.example.com' do
    assert_status 'NOERROR'
    assert_flags 'qr', 'aa'
    assert_answer '192.0.2.10'
    assert_authority 'ns1.example.com', 'ns2.example.com'
  end
end

test 'Simple CNAME query' do
  query 'b.example.com' do
    assert_status 'NOERROR'
    assert_flags 'qr', 'aa'
    assert_answer 'a.example.com', 'CNAME'
    assert_answer '192.0.2.10'
    assert_authority 'ns1.example.com', 'ns2.example.com'
  end
end

test 'Query nonexistent domain name' do
  query 'nonexistent.example.com' do
    assert_status 'NXDOMAIN'
    assert_flags 'qr', 'aa'
    assert_authority_type 'SOA'
  end
end

test 'Query nonexistent zone' do
  query 'zone.nonexistent' do
    assert_status 'SERVFAIL'
    assert_flags 'qr'
  end
end
