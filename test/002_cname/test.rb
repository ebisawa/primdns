require 'unittest.rb'

test 'Query CNAME record' do
  query 'b.example.com' do
    assert_status 'NOERROR'
    assert_flags 'qr', 'aa'
    assert_answer 'a.example.com', 'CNAME'
    assert_answer '192.0.2.10'
    assert_authority 'ns1.example.com', 'ns2.example.com'
  end
end

test 'Query CNAME itself' do
  query 'CNAME b.example.com' do
    assert_status 'NOERROR'
    assert_flags 'qr', 'aa'
    assert_answer 'a.example.com', 'CNAME'
    assert_authority 'ns1.example.com', 'ns2.example.com'
  end
end

test 'Query CNAME itself (refering to nonexistent name)' do
  query 'CNAME c.example.com' do
    assert_status 'NXDOMAIN'
    assert_flags 'qr', 'aa'
    assert_answer 'nonexistent.example.com', 'CNAME'
    assert_authority_type 'SOA'
  end
end

test 'Query CNAME itself (refering to out-of-zone name)' do
  query 'CNAME d.example.com' do
    assert_status 'NOERROR'
    assert_flags 'qr', 'aa'
    assert_answer 'nonexistent.example.org', 'CNAME'
    assert_noauthority
  end
end

test 'Query CNAME itself (referriing to delegated zone)' do
  query 'CNAME e.example.com' do
    assert_status 'NOERROR'
    assert_flags 'qr', 'aa'
    assert_answer 'x.sub.example.com', 'CNAME'
    assert_authority 'ns.example.jp'
    assert_noadditional
  end
end
