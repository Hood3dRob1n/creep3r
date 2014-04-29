# My own Ruby implementation of the findmyhash.py Tool I have loved for so many years...


# Class for Hash Searching online
# Methods to query individual sites or all
class HashFinder
  def initialize(hash_to_find='32250170a0dca92d53ec9624f336ca24', stop_on_success=true, htype='MD5') # pass123
    supported = [ 'MD4', 'MD5', 'LM', 'NTLM', 'LM:NTLM', 'MYSQL', 'SHA1' ]
    @http = EasyCurb.new
    @sos = stop_on_success
    @hash_to_find = hash_to_find
    if supported.include?(htype)
      @hash_type = htype
    else
      @hash_type = 'MD5'
    end
  end

  # Run all hash searches and return results or nil
  # Returns hash array of match or nil
  def total_hash_search(hash_to_find=@hash_to_find, stop_on_success=@sos, verbose=true)
    matches={}
    while(true)
      case @hash_type
      when 'MD4'
        result = leakdb_hash_search(hash_to_find, verbose)
        if not result.nil?
          matches.store('api.leakdb.abusix.com', result)
          break if stop_on_success
        end
      when 'MD5'
        result = leakdb_hash_search(hash_to_find, verbose)
        if not result.nil?
          matches.store('api.leakdb.abusix.com', result)
          break if stop_on_success
        end

        result = darkbyte_hash_search(hash_to_find, verbose)
        if not result.nil?
          matches.store('md5.darkbyte.ru', result)
          break if stop_on_success
        end

        result = gromweb_hash_search(hash_to_find, verbose)
        if not result.nil?
          matches.store('md5.gromweb.com', result)
          break if stop_on_success
        end

        result = md5comcn_hash_search(hash_to_find, verbose)
        if not result.nil?
          matches.store('md5.com.cn', result)
          break if stop_on_success
        end

        result = md5onlinenet_hash_search(hash_to_find, verbose)
        if not result.nil?
          matches.store('md5online.net', result)
          break if stop_on_success
        end

        result = md5onlineorg_hash_search(hash_to_find, verbose)
        if not result.nil?
          matches.store('md5online.org', result)
          break if stop_on_success
        end

        result = myaddr_hash_search(hash_to_find, verbose)
        if not result.nil?
          matches.store('md5.my-addr.com', result)
          break if stop_on_success
        end

        result = noisette_hash_search(hash_to_find, verbose)
        if not result.nil?
          matches.store('md5.noisette.ch', result)
          break if stop_on_success
        end

        result = netmd5crack_hash_search(hash_to_find, verbose)
        if not result.nil?
          matches.store('netmd5crack.com', result)
          break if stop_on_success
        end

        result = sans_hash_search(hash_to_find, verbose)
        if not result.nil?
          matches.store('isc.sans.edu', result)
          break if stop_on_success
        end

        result = stringfunction_hash_search(hash_to_find, verbose)
        if not result.nil?
          matches.store('stringfunction.com', result)
          break if stop_on_success
        end
      when 'LM'
        result = it64_hash_search(hash_to_find, verbose)
        if not result.nil?
          matches.store('rainbowtables.it64.com', result)
          break if stop_on_success
        end

        result = leakdb_hash_search(hash_to_find, verbose)
        if not result.nil?
          matches.store('api.leakdb.abusix.com', result)
          break if stop_on_success
        end
      when 'NTLM'
        result = leakdb_hash_search(hash_to_find, verbose)
        if not result.nil?
          matches.store('api.leakdb.abusix.com', result)
          break if stop_on_success
        end
      when 'LM:NTLM'
        result = leakdb_hash_search(hash_to_find, verbose)
        if not result.nil?
          matches.store('api.leakdb.abusix.com', result)
          break if stop_on_success
        end
      when 'MYSQL'
        result = leakdb_hash_search(hash_to_find, verbose)
        if not result.nil?
          matches.store('api.leakdb.abusix.com', result)
          break if stop_on_success
        end
      when 'SHA1'
        result = leakdb_hash_search(hash_to_find, verbose)
        if not result.nil?
          matches.store('api.leakdb.abusix.com', result)
          break if stop_on_success
        end

        result = sans_hash_search(hash_to_find, verbose)
        if not result.nil?
          matches.store('isc.sans.edu', result)
          break if stop_on_success
        end

        result = stringfunction_hash_search(hash_to_find, verbose)
        if not result.nil?
          matches.store('stringfunction.com', result)
          break if stop_on_success
        end
      end
      break # tried all sites by now...
    end
    return matches
  end

  # Run hash search against md5.darkbyte.ru
  # Returns plain-text match or nil
  def darkbyte_hash_search(hash_to_find=@hash_to_find, verbose=true)
    if @hash_type == 'MD5'
      res = @http.get("http://md5.darkbyte.ru/api.php?q=#{hash_to_find}")
      if not res[0].nil? and res[0].strip.chomp != ''
        if verbose
          print_good("Match Found: md5.darkbyte.ru")
          puts "   [".light_green + "+".white + "] ".light_green + "Hash:  #{hash_to_find}".white
          puts "   [".light_green + "+".white + "] ".light_green + "Plain-Text: #{res[0].strip.chomp}".white
        end
        return res[0]
      else
        print_error("No Results from: md5.darkbyte.ru") if verbose
        return nil
      end
    else
      print_error("#{@hash_type} not supported for: md5.darkbyte.ru") if verbose
      return nil
    end
  end

  # Run hash search against md5.gromweb.com
  # Returns plain-text match or nil
  def gromweb_hash_search(hash_to_find=@hash_to_find, verbose=true)
    if @hash_type == 'MD5'
      res = @http.get("http://md5.gromweb.com/query/#{hash_to_find}")
      if not res[0].nil? and res[0].strip.chomp != ''
        if verbose
          print_good("Match Found: md5.gromweb.com")
          puts "   [".light_green + "+".white + "] ".light_green + "Hash:  #{hash_to_find}".white
          puts "   [".light_green + "+".white + "] ".light_green + "Plain-Text: #{res[0].strip.chomp}".white
        end
        return res[0]
      else
        print_error("No Results from: md5.gromweb.com") if verbose
        return nil
      end
    else
      print_error("#{@hash_type} not supported for: md5.gromweb.com") if verbose
      return nil
    end
  end

  # Run hash search against it64.com
  # Returns plain-text match or nil
  def it64_hash_search(hash_to_find=@hash_to_find, verbose=true)
    if @hash_type == 'LM'
      agent = Mechanize.new
      begin
        agent.user_agent = $config['HTTP']['HTTP_USER_AGENT']
        if $config['HTTP']['PROXY']
          if $config['HTTP']['PROXY_AUTH']
            agent.set_proxy($config['HTTP']['PROXY_IP'], $config['HTTP']['PROXY_PORT'].to_i, user=$config['HTTP']['PROXY_USER'], pass=$config['HTTP']['PROXY_PASS'])
          else
            agent.set_proxy($config['HTTP']['PROXY_IP'], $config['HTTP']['PROXY_PORT'].to_i)
          end
        end
        # Fill out form and run search for hash
        page = agent.get('http://rainbowtables.it64.com/p3.php')          # Get page
        search_form = page.form_with(:action => 'p3.php')                 # find form to fill out
        search_form.hashe = hash_to_find                                  # set hash to find value
        button = search_form.button_with(:name => 'ifik')                 # Identify submit button
        page = agent.submit(search_form, button)                          # submit form and return new page
        pieces = page.body.scan(/CRACKED&nbsp;<\/TD><TD>&nbsp;(.{1,7})&nbsp;<\/TD><\/TR>/)
        if not pieces.nil? and pieces.size > 0
          plain_jane = pieces.join()
          if verbose
            print_good("Match Found: rainbowtables.it64.com")
            puts "   [".light_green + "+".white + "] ".light_green + "Hash:  #{hash_to_find}".white
            puts "   [".light_green + "+".white + "] ".light_green + "Plain-Text: #{plain_jane}".white
          end
          return plain_jane
        end
      rescue OpenSSL::SSL::SSLError,Errno::ETIMEDOUT,Net::HTTP::Persistent::Error,NoMethodError,Zlib::DataError,Mechanize::ResponseCodeError => e
        print_error("Problem Communicating with: rainbowtables.it64.com") if verbose
        return nil
      end
      print_error("No Results from: rainbowtables.it64.com") if verbose
      return nil
    else
      print_error("#{@hash_type} not supported for: rainbowtables.it64.com") if verbose
      return nil
    end
  end

  # Run hash search against api.leakdb.abusix.com
  # Returns plain-text match or nil
  def leakdb_hash_search(hash_to_find=@hash_to_find, verbose=true)
    if @hash_type =~ /MD4|MD5|SHA1|SHA256|SHA512|LM|NT|MYSQL/
      res = @http.get("http://api.leakdb.abusix.com/?t=#{hash_to_find}")
      if not res[0].nil? and res[0].strip.chomp != ''
        if res[0] =~ /plaintext=(.+)/
          plain_jane = $1.strip.chomp
          if verbose
            print_good("Match Found: api.leakdb.abusix.com")
            puts "   [".light_green + "+".white + "] ".light_green + "Hash:  #{hash_to_find}".white
            puts "   [".light_green + "+".white + "] ".light_green + "Plain-Text: #{plain_jane.strip.chomp}".white
          end
          return plain_jane
        end
      else
        print_error("No Results from: api.leakdb.abusix.com") if verbose
        return nil
      end
    else
      print_error("#{@hash_type} not supported for: api.leakdb.abusix.com") if verbose
      return nil
    end
  end

  # Run hash search against md5.com.cn
  # Returns plain-text match or nil
  def md5comcn_hash_search(hash_to_find=@hash_to_find, verbose=true)
    if @hash_type == 'MD5'
      agent = Mechanize.new
      begin
        agent.user_agent = $config['HTTP']['HTTP_USER_AGENT']
        if $config['HTTP']['PROXY']
          if $config['HTTP']['PROXY_AUTH']
            agent.set_proxy($config['HTTP']['PROXY_IP'], $config['HTTP']['PROXY_PORT'].to_i, user=$config['HTTP']['PROXY_USER'], pass=$config['HTTP']['PROXY_PASS'])
          else
            agent.set_proxy($config['HTTP']['PROXY_IP'], $config['HTTP']['PROXY_PORT'].to_i)
          end
        end
        # Find form, enter hash, run search...
        page = agent.get('http://md5.com.cn/')
        search_form = page.form_with( :action => '/md5reverse' )
        search_form.md = hash_to_find
        button = search_form.button_with( :name => 'submit' )
        page = agent.submit(search_form, button) # submit form and return new page
        if page.body =~ /<label class="res count label b">Md5:<\/label>\s+<span class="res green">#{hash_to_find}\s+<!--#{hash_to_find}-->.+<\/span><br\/>\s+<label class="res count label">Result:<\/label>\s+<span class="res green">(.+)<\/span>/
          plain_jane = $1.strip.chomp
          if verbose
            print_good("Match Found: md5.com.cn")
            puts "   [".light_green + "+".white + "] ".light_green + "Hash:  #{hash_to_find}".white
            puts "   [".light_green + "+".white + "] ".light_green + "Plain-Text: #{plain_jane}".white
          end
          return plain_jane
        end
      rescue OpenSSL::SSL::SSLError,Errno::ETIMEDOUT,Net::HTTP::Persistent::Error,NoMethodError,Zlib::DataError,Mechanize::ResponseCodeError => e
        print_error("Problem Communicating with: md5.com.cn") if verbose
        return nil
      end
      print_error("No Results from: md5.com.cn") if verbose
      return nil
    else
      print_error("#{@hash_type} not supported for: md5.com.cn") if verbose
      return nil
    end
  end

  # Run hash search against md5online.net
  # Returns plain-text match or nil
  def md5onlinenet_hash_search(hash_to_find=@hash_to_find, verbose=true)
    if @hash_type == 'MD5'
      agent = Mechanize.new
      begin
        agent.user_agent = $config['HTTP']['HTTP_USER_AGENT']
        if $config['HTTP']['PROXY']
          if $config['HTTP']['PROXY_AUTH']
            agent.set_proxy($config['HTTP']['PROXY_IP'], $config['HTTP']['PROXY_PORT'].to_i, user=$config['HTTP']['PROXY_USER'], pass=$config['HTTP']['PROXY_PASS'])
          else
            agent.set_proxy($config['HTTP']['PROXY_IP'], $config['HTTP']['PROXY_PORT'].to_i)
          end
        end
        # Fill out form and run search for hash
        page = agent.get('http://md5online.net')                          # Get page
        search_form = page.form_with(:action => 'http://md5online.net/')  # find form to fill out
        search_form.pass = hash_to_find                                   # set hash to find value
        page = agent.submit(search_form, search_form.buttons.first)       # submit form and return new page
        if page.body =~ /<center><p>md5 :<b>#{hash_to_find}<\/b> <br>pass : <b>(.+)<\/b><\/p><\/table>/
          plain_jane = $1.to_s.strip.chomp
          if verbose
            print_good("Match Found: md5online.net")
            puts "   [".light_green + "+".white + "] ".light_green + "Hash:  #{hash_to_find}".white
            puts "   [".light_green + "+".white + "] ".light_green + "Plain-Text: #{plain_jane}".white
          end
          return plain_jane
        end
      rescue OpenSSL::SSL::SSLError,Errno::ETIMEDOUT,Net::HTTP::Persistent::Error,NoMethodError,Zlib::DataError,Mechanize::ResponseCodeError => e
        print_error("Problem Communicating with: md5online.net") if verbose
        return nil
      end
      print_error("No Results from: md5online.net") if verbose
      return nil
    else
      print_error("#{@hash_type} not supported for: md5online.net") if verbose
      return nil
    end
  end

  # Run hash search against md5online.org
  # Returns plain-text match or nil
  def md5onlineorg_hash_search(hash_to_find=@hash_to_find, verbose=true)
    if @hash_type == 'MD5'
      agent = Mechanize.new
      begin
        agent.user_agent = $config['HTTP']['HTTP_USER_AGENT']
        if $config['HTTP']['PROXY']
          if $config['HTTP']['PROXY_AUTH']
            agent.set_proxy($config['HTTP']['PROXY_IP'], $config['HTTP']['PROXY_PORT'].to_i, user=$config['HTTP']['PROXY_USER'], pass=$config['HTTP']['PROXY_PASS'])
          else
            agent.set_proxy($config['HTTP']['PROXY_IP'], $config['HTTP']['PROXY_PORT'].to_i)
          end
        end
        # Fill out form and run search for hash
        page = agent.get('http://md5online.org')                          # Get page
        search_form = page.forms.first                                    # find form to fill out
        search_form.md5 = hash_to_find                                    # set hash to find value
        page = agent.submit(search_form, search_form.buttons.first)       # submit form and return new page
        if page.body =~ /<span class="result" .+>Found : <b>(.+)<\/b><\/span>.+\(hash = #{hash_to_find }\)<\/span>/
          plain_jane = $1.to_s.strip.chomp
          if verbose
            print_good("Match Found: md5online.org")
            puts "   [".light_green + "+".white + "] ".light_green + "Hash:  #{hash_to_find}".white
            puts "   [".light_green + "+".white + "] ".light_green + "Plain-Text: #{plain_jane}".white
          end
          return plain_jane
        end
      rescue OpenSSL::SSL::SSLError,Errno::ETIMEDOUT,Net::HTTP::Persistent::Error,NoMethodError,Zlib::DataError,Mechanize::ResponseCodeError => e
        print_error("Problem Communicating with: md5online.org") if verbose
        return nil
      end
      print_error("No Results from: md5online.org") if verbose
      return nil
    else
      print_error("#{@hash_type} not supported for: md5online.net") if verbose
      return nil
    end
  end

  # Run hash search against md5.my-addr.com
  # Returns plain-text match or nil
  def myaddr_hash_search(hash_to_find=@hash_to_find, verbose=true)
    if @hash_type == 'MD5'
      agent = Mechanize.new
      begin
        agent.user_agent = $config['HTTP']['HTTP_USER_AGENT']
        if $config['HTTP']['PROXY']
          if $config['HTTP']['PROXY_AUTH']
            agent.set_proxy($config['HTTP']['PROXY_IP'], $config['HTTP']['PROXY_PORT'].to_i, user=$config['HTTP']['PROXY_USER'], pass=$config['HTTP']['PROXY_PASS'])
          else
            agent.set_proxy($config['HTTP']['PROXY_IP'], $config['HTTP']['PROXY_PORT'].to_i)
          end
        end
        # Find form, enter hash, run search...
        page = agent.get('http://md5.my-addr.com/md5_decrypt-md5_cracker_online/md5_decoder_tool.php')
        search_form = page.form_with(:name => 'f1') # our form
        search_form.md5 = hash_to_find              # set hash in form field value
        page = agent.submit(search_form, search_form.buttons.first) # submit form and return new page
        # Check for match found to requesting hash
        checking_hash = /<div class='white_bg_title'><span class='middle_title'>MD5 hash<\/span>: #{hash_to_find}<\/div>\s<br>/
        bad_news = /<div class='error_title'>Hash "#{hash_to_find}" not found in database<\/div>/
        if page.body =~ checking_hash and not page.body =~ bad_news
          if page.body =~ /\s<div class='white_bg_title'><span class='middle_title'>Hashed string<\/span>: (.+)<\/div>/
            plain_jane = $1.to_s.strip.chomp
            if verbose
              print_good("Match Found: md5.my-addr.com")
              puts "   [".light_green + "+".white + "] ".light_green + "Hash:  #{hash_to_find}".white
              puts "   [".light_green + "+".white + "] ".light_green + "Plain-Text: #{plain_jane}".white
            end
            return plain_jane
          end
        end
      rescue OpenSSL::SSL::SSLError,Errno::ETIMEDOUT,Net::HTTP::Persistent::Error,NoMethodError,Zlib::DataError,Mechanize::ResponseCodeError => e
        print_error("Problem Communicating with: md5.my-addr.com") if verbose
        return nil
      end
      print_error("No Results from: md5.my-addr.com") if verbose
      return nil
    else
      print_error("#{@hash_type} not supported for: md5.my-addr.com") if verbose
      return nil
    end
  end

  # Run hash search against netmd5crack.com
  # Returns plain-text match or nil
  def netmd5crack_hash_search(hash_to_find=@hash_to_find, verbose=true)
    if @hash_type == 'MD5'
      res = @http.get("http://www.netmd5crack.com/cgi-bin/Crack.py?InputHash=#{hash_to_find}")
      if res[0] =~ /<tr><td class="border">[a-fA-F\d]{32}<\/td><td class="border">(.+)<\/td><\/tr><\/table>/
        plain_jane = $1.to_s.strip.chomp
        if plain_jane =~ /Sorry, we don't have that hash in our database/
          print_error("No Results from: netmd5crack.com") if verbose
          return nil
        end
        if verbose
          print_good("Match Found: netmd5crack.com")
          puts "   [".light_green + "+".white + "] ".light_green + "Hash:  #{hash_to_find}".white
          puts "   [".light_green + "+".white + "] ".light_green + "Plain-Text: #{plain_jane}".white
        end
        return plain_jane
      else
        print_error("No Results from: netmd5crack.com") if verbose
        return nil
      end
    else
      print_error("#{@hash_type} not supported for: netmd5crack.com") if verbose
      return nil
    end
  end

  # Run hash search against md5.noisette.ch
  # Returns plain-text match or nil
  def noisette_hash_search(hash_to_find=@hash_to_find, verbose=true)
    if @hash_type == 'MD5'
      agent = Mechanize.new
      begin
        agent.user_agent = $config['HTTP']['HTTP_USER_AGENT']
        if $config['HTTP']['PROXY']
          if $config['HTTP']['PROXY_AUTH']
            agent.set_proxy($config['HTTP']['PROXY_IP'], $config['HTTP']['PROXY_PORT'].to_i, user=$config['HTTP']['PROXY_USER'], pass=$config['HTTP']['PROXY_PASS'])
          else
            agent.set_proxy($config['HTTP']['PROXY_IP'], $config['HTTP']['PROXY_PORT'].to_i)
          end
        end
        # Find form, enter hash, run search...
        page = agent.get('http://md5.noisette.ch/index.php')
        search_form = page.forms.first
        search_form.hash = hash_to_find
        page = agent.submit(search_form, search_form.buttons.first) # submit form and return new page
        if not page.body =~ /<div class="error">No corresponding md5 found for "#{hash_to_find}"<\/div>/
          plain_jane = page.forms[1].fields[0].value
          if verbose
            print_good("Match Found: md5.noisette.ch")
            puts "   [".light_green + "+".white + "] ".light_green + "Hash:  #{hash_to_find}".white
            puts "   [".light_green + "+".white + "] ".light_green + "Plain-Text: #{plain_jane}".white
          end
          return plain_jane
        end
      rescue OpenSSL::SSL::SSLError,Errno::ETIMEDOUT,Net::HTTP::Persistent::Error,NoMethodError,Zlib::DataError,Mechanize::ResponseCodeError => e
        print_error("Problem Communicating with: md5.noisette.ch") if verbose
        return nil
      end
      print_error("No Results from: md5.noisette.ch") if verbose
      return nil
    else
      print_error("#{@hash_type} not supported for: md5.noisette.ch") if verbose
      return nil
    end
  end

  # Run hash search against isc.sans.edu
  # Returns plain-text match or nil
  def sans_hash_search(hash_to_find=@hash_to_find, verbose=true)
    if @hash_type == 'MD5' or @hash_type == 'SHA1'
      agent = Mechanize.new
      begin
        agent.user_agent = $config['HTTP']['HTTP_USER_AGENT']
        if $config['HTTP']['PROXY']
          if $config['HTTP']['PROXY_AUTH']
            agent.set_proxy($config['HTTP']['PROXY_IP'], $config['HTTP']['PROXY_PORT'].to_i, user=$config['HTTP']['PROXY_USER'], pass=$config['HTTP']['PROXY_PASS'])
          else
            agent.set_proxy($config['HTTP']['PROXY_IP'], $config['HTTP']['PROXY_PORT'].to_i)
          end
        end
        # Find form, enter hash, run search...
        page = agent.get('https://isc.sans.edu/tools/reversehash.html')
        search_form = page.form_with( :action => "/tools/reversehash.html" )
        search_form.text = hash_to_find
        button = search_form.button_with(:name => 'submit')
        page = agent.submit(search_form, button) # submit form and return new page
page.body =~ /Sorry, no solution found/
        if not page.body =~ /Sorry, no solution found/
          if page.body =~ /<\/p>\s+<p style="border: 1px solid; padding:6px;">\s+(.+) hash #{hash_to_find} = (.+)\s+<\/p><br \/>/
            type = $1
            plain_jane = $2.strip.chomp
            if verbose
              print_good("Match Found: isc.sans.edu")
              puts "   [".light_green + "+".white + "] ".light_green + "Hash:  #{hash_to_find}".white
              puts "   [".light_green + "+".white + "] ".light_green + "Plain-Text: #{plain_jane}".white
            end
            return plain_jane
          end
        end
      rescue OpenSSL::SSL::SSLError,Errno::ETIMEDOUT,Net::HTTP::Persistent::Error,NoMethodError,Zlib::DataError,Mechanize::ResponseCodeError => e
        print_error("Problem Communicating with: isc.sans.edu") if verbose
        return nil
      end
      print_error("No Results from: isc.sans.edu") if verbose
      return nil
    else
      print_error("#{@hash_type} not supported for: isc.sans.edu") if verbose
      return nil
    end
  end

  # Run hash search against stringfunction.com
  # Returns plain-text match or nil
  def stringfunction_hash_search(hash_to_find=@hash_to_find, verbose=true)
    if @hash_type == 'MD5' or @hash_type == 'SHA1'
      agent = Mechanize.new
      begin
        agent.user_agent = $config['HTTP']['HTTP_USER_AGENT']
        if $config['HTTP']['PROXY']
          if $config['HTTP']['PROXY_AUTH']
            agent.set_proxy($config['HTTP']['PROXY_IP'], $config['HTTP']['PROXY_PORT'].to_i, user=$config['HTTP']['PROXY_USER'], pass=$config['HTTP']['PROXY_PASS'])
          else
            agent.set_proxy($config['HTTP']['PROXY_IP'], $config['HTTP']['PROXY_PORT'].to_i)
          end
        end
        found=false
        # Find form, enter hash, run search...
        if @hash_type == 'SHA1'
          page = agent.get('http://www.stringfunction.com/sha1-decrypter.html')
          search_form = page.form_with( :action => "./sha1-decrypter.html" )
          search_form.string = hash_to_find
        else
          page = agent.get('http://www.stringfunction.com/md5-decrypter.html')
          search_form = page.form_with( :action => "./md5-decrypter.html" )
          search_form.string_md5 = hash_to_find
        end
        button = search_form.button_with(:value=>'Decrypt')
        page = agent.submit(search_form, button) # submit form and return new page
        if @hash_type == 'SHA1'
          if page.body =~ /<textarea class="textarea-input-tool-b" rows="10" cols="50" name="result">(.+)\s+<\/textarea>/
            plain_jane = $1.strip.chomp
            found=true
          end
        else
          if page.body =~ /<textarea class="textarea-input-tool-b" rows="10" cols="50" name="result" .+">(.+)<\/textarea>/
            plain_jane = $1.strip.chomp
            found=true
          end
        end
        if found
          if verbose
            print_good("Match Found: stringfunction.com")
            puts "   [".light_green + "+".white + "] ".light_green + "Hash:  #{hash_to_find}".white
            puts "   [".light_green + "+".white + "] ".light_green + "Plain-Text: #{plain_jane}".white
          end
          return plain_jane
        end
      rescue OpenSSL::SSL::SSLError,Errno::ETIMEDOUT,Net::HTTP::Persistent::Error,NoMethodError,Zlib::DataError,Mechanize::ResponseCodeError => e
        print_error("Problem Communicating with: stringfunction.com") if verbose
        return nil
      end
      print_error("No Results from: stringfunction.com") if verbose
      return nil
    else
      print_error("#{@hash_type} not supported for: stringfunction.com") if verbose
      return nil
    end
  end
end
