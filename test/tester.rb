#!/usr/bin/env ruby
require 'pp'

class Tester
  TEST_PORT = 5353
  PRIMD_DIR = '../primd'
  SCRIPT_DIR = '../scripts'

  def initialize(testdir)
    @testdir = testdir
    @ok = true
    @status = nil; @flags = []; @records = {}
  end

  def ok?
    @ok
  end

  def prepare
    system("#{SCRIPT_DIR}/primdns-updatezone #{@testdir}")
    start_primd
  end

  def start
    open("#{@testdir}/test.rb") do |io|
      lines = io.readlines
      instance_eval(lines.join)
    end
    system("killall primd")
  end

  private
  def start_primd
    fork do
      exec("#{PRIMD_DIR}/primd -d -f -p #{TEST_PORT} -c #{@testdir}/primd.conf >#{@testdir}/test.log")
    end
  end

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

  def title(t)
    puts "- #{@testdir}: #{t} -"
  end

  def query(q)
    r = `dig -p #{TEST_PORT} @127.0.0.1 #{q}`
    parse_result(r)

    pp @status
    pp @flags
    pp @records
  end

  def assert_status(status)
    if @status == status
      ok(status)
    else
      ng(status)
    end
  end

  def assert_flag(flag)
    if @flags.include?(flag)
      ok(flag)
    else
      ng(flag)
    end
  end

  def assert_answer(rdata, type = nil)
    @records[:answer].each do |answer|
      if type == nil || answer[:type] == type
        if answer[:rdata] == rdata
          ok(rdata, type)
          return
        end
      end
    end
    ng(rdata, type)
  end

  def assert_authority(name)
    @records[:authority].each do |ns|
      if ns[:rdata] == name
        ok(name)
        return
      end
    end
    ng(name)
  end

  def assert_authority_type(type)
    @records[:authority].each do |ns|
      if ns[:type] == type
        ok(type)
        return
      end
    end
    ng(type)
  end

  def ok(param, type = nil)
    t = (type != nil) ? "/#{type}" : ''
    caller_name = caller[0].sub(/.*`(.+)'.*/, '\1')
    puts "[ OK ] #{caller_name} \"#{param}\"#{t}"
  end

  def ng(param, type = nil)
    t = (type != nil) ? "#{type} " : ''
    caller_name = caller[0].sub(/.*`(.+)'.*/, '\1')
    puts "[ FAIL ] #{caller_name} \"#{param}\"#{t}"
    @ok = false
  end
end


Dir.glob('*') do |dir|
  if File.directory?(dir)
    tester = Tester.new(dir)
    tester.prepare
    sleep 0.5

    tester.start
  end
end
