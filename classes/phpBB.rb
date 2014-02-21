# phpBB Specific Checks and/or Audits
# Just a few version checks for now, more to come...


class PHPBBChecks
  def initialize(link='http://somesite.com/forum/')
    @url=link.sub(/\/$/, '')
    @site = link.chomp.sub('http://', '').sub('https://', '').sub('www.', '').sub(/\/$/, '')
    foo=@site.split('/')
    if foo.size > 1
      @site=foo[0]                    # Host or target domain
    end
    @http=EasyCurb.new
  end

  # Simple Checks for confirming phpBB CMS
  # Returns true or false
  def body_check(body)
    if body =~ /src=.+\/logo_phpBB.gif|We request you retain the full copyright notice below including the link to www.phpbb.com./i or (body =~ /href=.+www.phpbb.com/i and body =~ /powered by/i)
      return true
    else
      return false
    end
  end

  # Check for phpBB Theme Config Files
  # Tells Version info in the comments and is fairly reliable as well
  # Returns version info if available or nil
  def theme_config_version_finder(link=@url, theme='prosilver')
    test = link + "/styles/#{theme}/style.cfg"
    res = @http.get(test)
    if res[1] == 200
      version = res[0].match(/version(\s+)=(\s+)(\w.*)/)
      return version
    end
    if not link =~ /\/forum\/|\/phpBB\//
      alts = [ '/forum', '/phpBB', '/phpBB2', '/phpBB3' ]
      alts.each do |p|
        test = link + p + "/styles/#{theme}/style.cfg"
        res = @http.get(test)
        if res[1] == 200
          version = res[0].match(/version(\s+)=(\s+)(\w.*)/)
          return version
        end
      end
    end
    return nil
  end

  # Determine PHPBB Version using known Changelog File MD5 checksum values
  # Borrowed from thesp0nge's gengiscan code found on github
  # https://github.com/thesp0nge/gengiscan
  def changelog_checksum_version_finder(link=@url)
    changelog_hashes = [
      { :md5=>'3a3a98deb01ca9a41d60d0cd30f61e22', :version=>'2.0.4' },
      { :md5=>'d469f1cee34e4fb55f265bec0f0c14a8', :version=>'2.0.5' },
      { :md5=>'5905fc107b1a68762ac0d06c0fecc7b9', :version=>'2.0.6' },
      { :md5=>'7e9a7f6fb9aa3fc3debbdc09ca1941de', :version=>'2.0.7' },
      { :md5=>'d0406ed8e5cf4bd82192f3c88bb7fcd2', :version=>'2.0.8' },
      { :md5=>'734f0ecaeb1dc40ce64c1af60d082dcc', :version=>'2.0.8a' },
      { :md5=>'603328ab56f740a8eba90d435132da9f', :version=>'2.0.9' },
      { :md5=>'6dca72f720e5fd098e33e06ff7617bc2', :version=>'2.0.10' },
      { :md5=>'1e11b01aac9fe84682596d2fa38c9265', :version=>'2.0.11' },
      { :md5=>'7262663177c2cb9440a3250989de1847', :version=>'2.0.12' },
      { :md5=>'11771948789983e496646c12eb2709e6', :version=>'2.0.13' },
      { :md5=>'bd9d2285839fb7e15a556f0ba2f7ae2c', :version=>'2.0.14' },
      { :md5=>'d636b63d299cbfb2948450e80d5be7d6', :version=>'2.0.15' },
      { :md5=>'d4d2f1e38096a4b32e22dff57773c62d', :version=>'2.0.16' },
      { :md5=>'bb29b25a9734d10328f970001f0295b3', :version=>'2.0.17' },
      { :md5=>'3058647f25b2d3d4804cd8e3e69a938f', :version=>'2.0.18' },
      { :md5=>'4880b1bc3a16771e934b7f69b4d87f2e', :version=>'2.0.19' },
      { :md5=>'b90c8f20ebfb920cc9ac332b60960cef', :version=>'2.0.20' },
      { :md5=>'90520361b651f583853fc7058fe10256', :version=>'2.0.21' },
      { :md5=>'4f1e462f7da7df826a07d1cf0faae4ae', :version=>'2.0.22' },
      { :md5=>'3eba9db5133b98df8a54abc55be34307', :version=>'2.0.23' },
      { :md5=>'e60f14eba6d00d56956c16f8a94ca140', :version=>'3.0-B5' },
      { :md5=>'e60f14eba6d00d56956c16f8a94ca140', :version=>'3.0-RC1' },
      { :md5=>'565c3b1933cda61295e54c1f141ef8b7', :version=>'3.0-RC2' },
      { :md5=>'f3f30e22403564e99e64d09f7f731dea', :version=>'3.0-RC3' },
      { :md5=>'63b9c4065b2aabda328a1c9b0677f986', :version=>'3.0-RC4' },
      { :md5=>'3d7aed030411838411a91ae4fcd213e4', :version=>'3.0-RC5' },
      { :md5=>'074417fdfca31a8d7349c88e8081d8cd', :version=>'3.0-RC6' },
      { :md5=>'2e139da54418cd096405d58e049bffd9', :version=>'3.0-RC7' },
      { :md5=>'e7de4c40a4fbf920aa0ef8d935564ed2', :version=>'3.0-RC8' },
      { :md5=>'dc1866d542cfcfface533b024ac3da77', :version=>'3.0.0' },
      { :md5=>'cfa612fc182916fd76467cce11c2e708', :version=>'3.0.1' },
      { :md5=>'fe1e7b8f3fc448ebfb7b2c1c5ec1e2d7', :version=>'3.0.1-RC1' },
      { :md5=>'59d04c38f084936b68551a0acccd3ea2', :version=>'3.0.2' },
      { :md5=>'f8b7389f4d5e61d0041430b5986378e2', :version=>'3.0.2-RC1' },
      { :md5=>'59d04c38f084936b68551a0acccd3ea2', :version=>'3.0.2-RC2' },
      { :md5=>'f4a6893faa9918962db5858f8b96c600', :version=>'3.0.3' },
      { :md5=>'f4a6893faa9918962db5858f8b96c600', :version=>'3.0.3-RC1' },
      { :md5=>'d638931f610f6a7073cf7bb43bf6370f', :version=>'3.0.4' },
      { :md5=>'d638931f610f6a7073cf7bb43bf6370f', :version=>'3.0.4-RC1' },
      { :md5=>'931e4dd982451b9baf4dbfa3a6d6da4e', :version=>'3.0.5' },
      { :md5=>'0fdcbb67c9773f490d3f0691a6dd4db9', :version=>'3.0.5-RC1' },
      { :md5=>'aedf28d7599038cf0b07e9404c69ffca', :version=>'3.0.6' },
      { :md5=>'5c40c50b6ca823ced16edac6aa8b2a1e', :version=>'3.0.6-RC1' },
      { :md5=>'38e7d25631ab2238a149c4880b69e42f', :version=>'3.0.6-RC2' },
      { :md5=>'4ac3967261c38fe4e934fe89f55f4a7a', :version=>'3.0.6-RC3' },
      { :md5=>'e1854e1d6c7058eb10aee1d0a2acd01b', :version=>'3.0.6-RC4' },
      { :md5=>'fc9c79e09cd265c44b025f08bd6bce30', :version=>'3.0.7' },
      { :md5=>'9354df71b5f83de36b0e51b833b2917b', :version=>'3.0.7-RC1' },
      { :md5=>'a2a05cfceecb678f843060ca9980dd5a', :version=>'3.0.7-RC2' },
      { :md5=>'ff4e8980be0af81ed2702dc9ef4c5e6c', :version=>'3.0.7-PL1' },
      { :md5=>'30f539c93140b2933765800b81e05707', :version=>'3.0.8' },
      { :md5=>'a544ff00e1242e21210ccc1466c02bac', :version=>'3.0.8-RC1' },
      { :md5=>'3f5c6ba11ff90cff9ced65833bdcfe8a', :version=>'3.0.9' },
      { :md5=>'eca607ffc079c0236bdc281d92c3db86', :version=>'3.0.9-RC1' },
      { :md5=>'94f5af08e7962466d50fcda1c1dc25a0', :version=>'3.0.9-RC2' },
      { :md5=>'ed7033cfc20fdf2b58bdebfb078cf8ae', :version=>'3.0.9-RC3' },
      { :md5=>'3f5c6ba11ff90cff9ced65833bdcfe8a', :version=>'3.0.9-RC4' },
      { :md5=>'4a57a4ad14dc5726fa76aea354c4a7b9', :version=>'3.0.10' },
      { :md5=>'ea02497f03a5a713c89a3a08da7e9818', :version=>'3.0.10-RC1' },
      { :md5=>'a69edd44fff3366c037d543a22d07ac3', :version=>'3.0.10-RC2' },
      { :md5=>'4a57a4ad14dc5726fa76aea354c4a7b9', :version=>'3.0.10-RC3' },
      { :md5=>'38c91a4e7015bd99ea0189be77d131a8', :version=>'3.0.11' } ,
      { :md5=>'69f1aad5d8eb2402f3290828232baced', :version=>'3.0.11-RC1' },
      { :md5=>'38c91a4e7015bd99ea0189be77d131a8', :version=>'3.0.11-RC2' },
      { :md5=>'fbe3fde19e59d20a1c400164e56fe972', :version=>'3.0.12-RC1' },
      { :md5=>'14fefb5e6fc8948aa3ef0aa50ee75571', :version=>'3.0.12-RC2' },
      { :md5=>'a52d4327967adf6b86cd5d18ebd49996', :version=>'3.0.12-RC3' },
      { :md5=>'6037b58ce1923581fa61941a6aaf815b', :version=>'3.0.12' }
    ]
    test = link + '/docs/CHANGELOG.html'
    res = @http.get(test)
    chksum = Digest::MD5.hexdigest(res[0])
    changelog_hashes.each do |hash|
      if hash[:md5] == chksum
        return hash[:version]
      end
    end

    if not link =~ /\/forum\/|\/phpBB\//
      alts = [ '/forum', '/phpBB', '/phpBB2', '/phpBB3' ]
      alts.each do |p|
        test = link + p + "/docs/CHANGELOG.html"
        res = @http.get(test)
        chksum = Digest::MD5.hexdigest(res[0])
        changelog_hashes.each do |hash|
          if hash[:md5] == chksum
            return hash[:version]
          end
        end
      end
    end

    return nil
  end
end






