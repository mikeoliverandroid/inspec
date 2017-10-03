# encoding: utf-8
# author: Christoph Hartmann
# author: Dominik Richter

require 'helper'
require 'inspec/resource'

describe 'Inspec::Resources::SSL' do
  it 'verify host reachable' do
    SSLShake.expects(:hello).at_least_once.returns({'success' => true})
    resource = load_resource('ssl', host: 'localhost')
    _(resource.enabled?).must_equal true
    _(resource.protocols.uniq).must_equal ["ssl2", "ssl3", "tls1.0", "tls1.1", "tls1.2"]
    _(resource.ciphers.include?('TLS_RSA_WITH_AES_128_CBC_SHA256')).must_equal true
    _(resource.ciphers.count).must_equal 681
  end

  it 'verify host unreachable' do
    SSLShake.expects(:hello).at_least_once.returns({"error"=>"Connection error Errno::ECONNREFUSED, can't connect to localhost:443."})
    resource = load_resource('ssl', host: 'localhost')
    _(resource.enabled?).must_equal false
    _(resource.protocols.uniq).must_equal ["ssl2", "ssl3", "tls1.0", "tls1.1", "tls1.2"]
    _(resource.ciphers.include?('TLS_RSA_WITH_AES_128_CBC_SHA256')).must_equal true
    _(resource.ciphers.count).must_equal 681
  end

  it 'error with nil host' do
    resource = load_resource('ssl', host: nil)
    err = assert_raises RuntimeError do
      resource.enabled?
    end
    expect = "Cannot determine host for SSL test. Please specify it or use a different target."
    err.to_s.must_equal expect
    _(resource.protocols.uniq).must_equal ["ssl2", "ssl3", "tls1.0", "tls1.1", "tls1.2"]
    _(resource.ciphers.include?('TLS_RSA_WITH_AES_128_CBC_SHA256')).must_equal true
    _(resource.ciphers.count).must_equal 681
  end
end
