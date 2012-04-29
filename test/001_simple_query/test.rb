require 'unittest.rb'

test 'Simple query' do
  query 'a.example.com' do
    assert_status 'NOERROR'
    assert_flags 'qr', 'aa'
    assert_answer '192.0.2.10'
    assert_authority 'ns1.example.com', 'ns2.example.com'
    assert_additional '192.0.2.1', '192.0.2.2'
    assert_additional '2001:db8::2:2'
  end
end

test 'Query NS record' do
  query 'ns2.example.com' do
    assert_status 'NOERROR'
    assert_flags 'qr', 'aa'
    assert_answer '192.0.2.2'
    assert_authority 'ns1.example.com', 'ns2.example.com'
    assert_additional '192.0.2.1'
    assert_additional '2001:db8::2:2'
    assert_additional '!192.0.2.2'
  end
end

test 'Query nonexistent domain name' do
  query 'nonexistent.example.com' do
    assert_status 'NXDOMAIN'
    assert_flags 'qr', 'aa'
    assert_noanswer
    assert_authority_type 'SOA'
  end
end

test 'Query nonexistent domain name' do
  query 'nonexistent.example.com' do
    assert_status 'NXDOMAIN'
    assert_flags 'qr', 'aa'
    assert_authority_type 'SOA'
  end
end

test 'Query nonexistent resource type' do
  query 'TXT a.example.com' do
    assert_status 'NOERROR'
    assert_flags 'qr', 'aa'
    assert_noanswer
    assert_authority_type 'SOA'
  end
end
