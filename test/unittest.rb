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

  def start
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
    if @digger.status == status
      pass(status)
    else
      fail(status)
    end
  end

  def assert_flags(flag)
    if @digger.flags.include?(flag)
      pass(flag)
    else
      fail(flag)
    end
  end

  def assert_answer(rdata, type = nil)
    @digger.records[:answer].each do |answer|
      if type == nil || answer[:type] == type
        if answer[:rdata] == rdata
          pass(rdata, type)
          return
        end
      end
    end
    fail(rdata, type)
  end

  def assert_authority(name)
    @digger.records[:authority].each do |ns|
      if ns[:rdata] == name
        pass(name)
        return
      end
    end
    fail(name)
  end

  def assert_authority_type(type)
    @digger.records[:authority].each do |ns|
      if ns[:type] == type
        pass(type)
        return
      end
    end
    fail(type)
  end

  private
  def pass(param, type = nil)
    t = (type != nil) ? "/#{type}" : ''
    caller_name = caller[0].sub(/.*`(.+)'.*/, '\1')
    puts "[ PASS ] #{caller_name} \"#{param}\"#{t}"
  end

  def fail(param, type = nil)
    t = (type != nil) ? "#{type} " : ''
    caller_name = caller[0].sub(/.*`(.+)'.*/, '\1')
    puts "[ FAIL ] #{caller_name} \"#{param}\"#{t}"
    @ok = false
  end
end


def test(title)
  puts "-- #{title} --"
  $test = Test.new
  $test.start
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