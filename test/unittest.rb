#!/usr/bin/env ruby
require 'pathname'
require 'pp'

TEST_PORT = 35353

class Digger
  attr_reader :result, :status, :flags, :records

  def initialize(addr = '127.0.0.1', port = TEST_PORT)
    @addr = addr; @port = port; @result = ''
    @status = nil; @flags = []; @records = {}
  end

  def query(q)
    @result = `dig -p #{@port} @#{@addr} #{q}`
    parse_result(@result)
  end

  private
  def parse_result(result)
    section = nil

    result.split("\n").each do |line|
      if line =~ /^;; ->>HEADER<<- .* status: (.*),/
        @status = $1
      end

      if line =~ /^;; flags: (.*);/
        @flags = $1.split(/\s+/)
      end

      section = :answer if line =~ /^;; ANSWER/
      section = :authority if line =~ /^;; AUTHORITY/
      section = :additional if line =~ /^;; ADDITIONAL/

      if line =~ /^([^\s]+)\s+(\d+)\s+IN\s+([^\s]+)\s+(.+)$/
        r = { :name => $1.chomp('.'), :ttl => $2, :type => $3, :rdata => $4.chomp('.') }
        @records[section] ||= []
        @records[section] << r
      end
    end
  end
end

class Primd
  def initialize(testdir, port = TEST_PORT)
    @port = port
    @testdir = testdir
    @basedir = primd_basedir
  end

  def start(index)
    system("#{@basedir}/scripts/primdns-updatezone #{@testdir}")
    fork do
      exec("#{@basedir}/primd/primd -d -f -p #{@port} -c #{@testdir}/primd.conf >#{@testdir}/test#{index}.log")
    end
  end

  def stop
    system("killall primd")
  end

  private
  def primd_basedir
    Pathname.new("#{@testdir}/../..").realpath
  end
end

class Test
  @@testdir = Pathname.new($0).realpath.dirname
  @@test_count = 0

  def initialize
    @primd = Primd.new(@@testdir)
    @digger = Digger.new
    @ok = true
    @@test_count += 1
  end

  def start(title)
    puts "\n>>> [#{File.basename(@@testdir)}:#{@@test_count}] #{title} <<<"
    @primd.start(@@test_count)
  end

  def finish
    @primd.stop

    open("#{@@testdir}/test#{@@test_count}.log", 'a') do |io|
      io.puts @digger.result
    end
  end

  def query(q)
    @digger.query(q)
  end

  def assert_status(status)
    @testmethod = current_method
    if @digger.status == status
      pass(status)
    else
      fail(status)
    end
  end

  def assert_flags(flag)
    @testmethod = current_method
    if @digger.flags.include?(flag)
      pass(flag)
    else
      fail(flag)
    end
  end

  def assert_noanswer
    @testmethod = current_method
    if @digger.records[:answer] == nil
      pass
    else
      fail
    end
  end

  def assert_noauthority
    @testmethod = current_method
    if @digger.records[:authority] == nil
      pass
    else
      fail
    end
  end

  def assert_noadditional
    @testmethod = current_method
    if @digger.records[:additional] == nil
      pass
    else
      fail
    end
  end

  def assert_answer(rdata, type = nil)
    assert_rdata(@digger.records[:answer], rdata, type)
  end

  def assert_answer_type(type)
    assert_type(@digger.records[:answer], type)
  end

  def assert_authority(rdata)
    assert_rdata(@digger.records[:authority], rdata)
  end

  def assert_authority_type(type)
    assert_type(@digger.records[:authority], type)
  end

  def assert_additional(rdata)
    assert_rdata(@digger.records[:additional], rdata)
  end

  def assert_additional_type(type)
    assert_type(@digger.records[:additional], type)
  end

  private
  def assert_rdata(records, rdata, type = nil)
    @testmethod = caller_method
    records.each do |r|
      next if type != nil && r[:type] != type
      if check_rdata(r[:rdata], rdata)
        pass(rdata, type)
        return
      end
    end
    fail(rdata, type)
  end

  def assert_type(records, type)
    @testmethod = caller_method
    records.each do |r|
      if check_rdata(r[:type], type)
        pass(type)
        return
      end
    end
    fail(rdata, type)
  end

  def check_rdata(rdata, adata)
    cnot = false
    if adata =~ /^!\s*(.+)$/
      adata = $1
      cnot = true
    end

    if rdata == adata
      return (cnot) ? false : true
    else
      return (cnot) ? true : false
    end
  end

  def pass(param = nil, type = nil)
    t = (type != nil) ? ", #{type}" : ''

    print "[ PASS ] #{@testmethod}"
    print " \"#{param}\"#{t}" if param != nil
    print "\n"
  end

  def fail(param = nil, type = nil)
    t = (type != nil) ? ", #{type}" : ''

    print "[ FAIL ] #{@testmethod}"
    print " \"#{param}\"#{t}" if param != nil
    print "\n"

    @ok = false
  end

  def current_method
    caller[0][/:in \`(.*?)\'\z/, 1]
  end

  def caller_method
    caller[1][/:in \`(.*?)\'\z/, 1]
  end
end


def test(title)
  $test = Test.new
  $test.start(title)
  sleep 0.05
  yield
  $test.finish
end

def query(q)
  $test.query(q)
  yield
end

def assert_status(status)
  $test.assert_status(status)
end

def assert_flags(*flags)
  flags.each do |flag|
    $test.assert_flags(flag)
  end
end

def assert_noanswer
  $test.assert_noanswer
end

def assert_noauthority
  $test.assert_noauthority
end

def assert_noadditional
  $test.assert_noadditional
end

def assert_answer(rdata, type = nil)
  $test.assert_answer(rdata, type)
end

def assert_authority(*names)
  names.each do |name|
    $test.assert_authority(name)
  end
end

def assert_authority_type(type)
  $test.assert_authority_type(type)
end

def assert_additional(*rdata)
  rdata.each do |rd|
    $test.assert_additional(rd)
  end
end
