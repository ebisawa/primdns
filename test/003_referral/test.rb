require 'unittest.rb'

test 'Referral test #1' do
  query 'x.sub1.example.com' do
    assert_status 'NOERROR'
    assert_flags 'qr', '!aa'
    assert_noanswer
    assert_authority 'ns1.sub1.example.com', 'ns2.sub1.example.com'
    assert_noadditional
  end
end

test 'Referral test #2' do
  query 'x.sub2.example.com' do
    assert_status 'NOERROR'
    assert_flags 'qr', '!aa'
    assert_noanswer
    assert_authority 'ns2.sub1.example.com', 'ns2.sub2.example.com'
    assert_additional '192.0.2.11', '2001:db8::2:11'
    assert_additional '192.0.2.12', '2001:db8::2:12'
  end
end
