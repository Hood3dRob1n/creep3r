# WordPress Specific Checks and/or Audits
# Just a few version checks for now, more to come...


class WordPressAudit
  def initialize(site)
    @site=site.sub(/\/$/, '')
    @host = site.chomp.sub('http://', '').sub('https://', '').sub('www.', '').sub(/\/$/, '')
    foo=@host.split('/')
    if foo.size > 1
      @host=foo[0]                    # Host or target domain
    end
    @http=EasyCurb.new
    @wp_paths=[ '', '/en', '/es', '/de', '/fr', '/wp', '/wpcms', '/wordpress', '/wp-content' '/cms', '/blog', '/blogview' ]
  end

  # WordPress Version Identification via Generator Meta Tag
  # Returns version on success, nil otherwise...
  def wp_generator_version_check(site=@site, verbose=true)
    @wp_paths.each do |p|
      link = site.sub(/\/$/, '') + p
      link += '/' if p == ''
      res = @http.get(site)
      if res[0] =~ /<meta name="generator" content="(WordPress \d+.\d+?.?\d+)" \/>/i
        wp_version = $1.chomp
        print_good("Generator Tag found!") if verbose
        print_line("   Version: #{wp_version}") if verbose
        wp_frontpage_check(res[0]) if verbose
        if not res[3].nil? and verbose
          blah_headers = [ 'Location', 'Date', 'Content-Type', 'Content-Length', 'Connection', 'Etag', 'Expires', 'Last-Modified', 'Pragma', 'Vary', 'Cache-Control', 'X-Pingback', 'Accept-Ranges', 'Transfer-Encoding', 'Link' ]
          print_good("Found Interesting Headers: ")
          res[3].split("\n").each do |header_line|
            header_name = header_line.split(':')[0]
            header_value = header_line.split(':')[1..-1].join(':')
            if not blah_headers.include?(header_name) and not header_name =~ /HTTP\/1\.1|^:$/ and header_name.strip.chomp != ''
              print_line("   #{header_name}: #{header_value}")
            end
          end
        end
        return wp_version
      end
    end
    print_error("No Generator Tag Found!") if verbose
    return nil
  end

  # WordPress Version Identification via default INSTALL.html file
  # Returns version on success, nil otherwise...
  def wp_install_version_check(site=@site, verbose=true)
    @wp_paths.each do |p|
      installer = site.sub(/\/$/, '') + p + '/INSTALL.html'
      res = @http.get(installer)
      if res[0] =~ /for (WordPress \d+.\d+?.?\d+)<\/title>/i
        wp_version = $1.chomp
        print_good("#{p}/INSTALL.html Found!") if verbose
        print_line("   Version: #{wp_version}") if verbose
        return wp_version
      elsif res[0] =~ /<br \/> Version (.*)/
        wp_version = $1.chomp
        print_good("#{p}/INSTALL.html Found!") if verbose
        print_line("   Version: #{wp_version}") if verbose
        return wp_version
      end
    end
    print_error("/INSTALL.html Not Found!") if verbose
    return nil
  end

  # WordPress Version Identification via default readme.html file
  # Returns version on success, nil otherwise...
  def wp_readme_version_check(site=@site, verbose=true)
    @wp_paths.each do |p|
      readme = site.sub(/\/$/, '') + p + '/readme.html'
      res = @http.get(readme)
      if res[0] =~ /for (WordPress \d+.\d+?.?\d+)<\/title>/i
        wp_version = $1.chomp
        print_good("#{p}/readme.html Found!") if verbose
        print_line("   Version: #{wp_version}") if verbose
        return wp_version
      elsif res[0] =~ /<br \/> Version (.*)/
        wp_version = $1.chomp
        print_good("#{p}/readme.html Found!") if verbose
        print_line("   Version: #{wp_version}") if verbose
        return wp_version
      elsif res[0] =~ /\s+<br \/>Version (\d\.\d\.\d)\s+/
        wp_version = $1.chomp
        print_good("#{p}/readme.html Found!") if verbose
        print_line("   Version: #{wp_version}") if verbose
        return wp_version
      end
    end
    print_error("/readme.html Not Found!") if verbose
    return nil
  end

  # WordPress Version Identification via RSS Feed's generator tag
  # Returns version on success, nil otherwise...
  def wp_rss_version_check(site=@site, verbose=true)
    @wp_paths.each do |p|
      feed = site.sub(/\/$/, '') + p + '/feed/'
      res = @http.get(feed)
      wp_frontpage_check(res[0]) if verbose
      if res[0] =~ /<generator>(.+)<\/generator>/i
        wp_version = $1.chomp.sub('http://wordpress.org/?v=', '')
        print_good("#{p}/feed/ Found!") if verbose
        print_line("   Version: #{wp_version}") if verbose
        return wp_version
      end
    end
    print_error("Unable to locate generator tag in RSS feed....") if verbose
    return nil
  end

  # Parse Response Body from Frontend Page
  # Check for active Theme & Plugins
  def wp_frontpage_check(resp_body)
    body = Nokogiri::HTML(resp_body)
    plugins = []
    themes = []
    links = []
    rpc = []
    begin
      generator_tag = body.at("meta[name='generator']")['content'].encode('UTF-8')
    rescue
      generator_tag = 'N/A'
    end
    # Grab href links...
    if not body.search("//a[@href]").nil?
      body.search("//a[@href]").each do |a|
        u = a['href']
        next if u.nil? or u.empty?
        links << u unless links.include?(u)
      end
    end
    # Add any available Image SRC Links
    if not body.search("//img[@src]").nil?
      body.search("//img[@src]").each do |a|
        u = a['src']
        next if u.nil? or u.empty?
        links << u unless links.include?(u)
      end
    end
    # And Script links too!
    if not body.search("//script[@src]").nil?
      body.search("//script[@src]").each do |a|
        u = a['src']
        next if u.nil? or u.empty?
        links << u unless links.include?(u)
      end
    end
    links.uniq.each do |url|
      if url =~ /\/wp-content\/themes\/(.+)\//
        themes << $1.strip.chomp
      end
      if url =~ /\/wp-content\/plugins\/(.+)\//
        plugins << $1.strip.chomp
      end
      if url =~ /\/xmlrpc\.php/i
        rpc << url
      end
    end
    if themes.size > 0
      if themes.uniq.size > 1
        print_status("Front Page Themes: ")
        themes.each do |theme|
          res = @http.get(@site.sub(/\/$/, '') + '/wp-content/themes/' + theme + '/style.css')
          if res[0] =~ /^Version: (.+)\s/i
            v=$1.strip.chomp
            print_line("   #{theme}, version: #{v}")
          else
            print_line("   #{theme}")
          end
        end
      else
        res = @http.get(@site.sub(/\/$/, '') + '/wp-content/themes/' + themes[0] + '/style.css')
        print_good("Current Theme: ")
        if res[0] =~ /^Version: (.+)\s/i
          v=$1.strip.chomp
          print_line("   #{themes[0]}, version: #{v}")
        else
          print_line("   #{themes[0]}")
        end
      end
    end
    if plugins.size > 0
      print_good("Front Page Plugins: ")
      plugins.uniq.each do |p|
        # Check and see if we can find out the specific plugin version info too
        res = @http.get(site.sub(/\/$/, '') + "/wp-content/plugins/#{p}/readme.txt")
        if res[0] =~ /^Stable tag: (.+)\s+/i
          print_line("   #{p}, version: #{$1.strip.chomp}")
        else
          print_line("   #{p}")
        end
      end
    end
    if rpc.size > 0
      print_good("XML-RPC Interface: ")
      rpc.uniq.each do |url|
        print_line("   #{url}")
      end
    end
  end

  # Simple check for rss-functions.php
  # This file contains function call that triggers verbose error w/path
  # EX:  Fatal error: Call to undefined function _deprecated_file() in /var/www/rss-functions.php on line 8
  def wp_rss_fpd(site=@site, verbose=true)
    res = @http.get(site.sub(/\/$/, '') + '/wp-includes/rss-functions.php')
    if res[0] =~ /<b>(\/.+\/.+)<\/b> on line/ # Capture the path from error
      fpd = $1.strip.chomp.split('/')[0..-2].join('/') << '/' # drop rss-functions.php
      return fpd
    end
    return nil
  end

  # WP Plugins Enumerator
  # Checks for Indexed Plugins Directory
  # Simply calls out the plugins found...
  def wp_plugin_enumerator(site=@site, verbose=true)
    @wp_paths.each do |p|
      plugins_dir = site.sub(/\/$/, '') + p + '/wp-content/plugins/'
      res = @http.get(plugins_dir)
      if res[0] =~ /<title>Index of.+\/wp-content\/plugins<\/title>|<h1>Index of.+\/wp-content\/plugins<\/h1>/i
        p1 = res[0].scan(/href="(.+)\/">?[a-z]/)
        p2 = res[0].scan(/href="(.+)\/"> ?[a-z]/)
        plugs = p1 + p2
        bad=['docs', 'inc', 'include', 'includes', 'locales' ] # Defaults and/or useless for our purposes...
        plugins=[]
        plugs.each {|x| plugins << x unless plugins.include?(x) or bad.include?(x) } 
        print_good("Plugins Directory Located: #{p}/wp-content/plugins/") if verbose
        print_good("Plugins Found: ") if verbose
        if verbose
          plugins.each do |x|
            # Check and see if we can find out the specific plugin version info too
            res = @http.get(site.sub(/\/$/, '') + p + "/wp-content/plugins/#{x}/readme.txt")
            if res[0] =~ /^Stable tag: (.+)\s+/i
              print_line("   #{x}, version: #{$1.strip.chomp}")
            else
              print_line("   #{x}")
            end
          end
        end
        return plugins.uniq
      end
    end
    return nil 
  end

  # Forcefull Plugin Check
  # We load the wp_plugins.txt list and check to see what seems to exist
  # Returns array of plugin names found to be installed, or nil
  def wp_plugin_forceful_enumerator(plist=nil, site=@site, verbose=true)
    if plist.nil?
      plist = HOME + 'fuzz/wp_plugins.txt'
    end
    if File.exists?(plist)
      plugin_list = []
      plugins = File.open(plist).readlines  # Load our Plugins list as array & Create the Stack
      print_status("Testing #{plugins.size} possible plugins, hang tight....")
      print_status("Running in #{plugins.size / 2500} chunks due to size of plugins list....") if plugins.size > 2500
      # While we have a stack, loop and run Curl multi Calls in chunks
      # I get crappy results when I send 40K at once, who knew?
      # This seems to resolve the issue and maintain reasonable speed...
      while plugins.size > 0
        queue=[]
        test_urls = []
        num = 2500
        if plugins.size < 2500
          num = plugins.size
        end
        (0..num.to_i).each {|x| z=plugins.pop; queue << z.chomp unless z.nil? or z.strip == ''  } # Seed our Queue & Shrink the Stack Down
        queue.each { |plugin_name| test_urls << site.sub(/\/$/, '') + "/wp-content/plugins/#{plugin_name.strip.chomp}/" } # Seed our plugin urls
        $config['HTTP']['PROGRESS'] = true        # Enable progressbar
        mresponses = @http.multi_get(test_urls)    # Curl Multi Mode Makes the Checks Faster
        print "\r"
        $config['HTTP']['PROGRESS'] = false       # Disable progressbar
        test_urls.each do |url| # Check results...
          if mresponses[url].response_code == 200 or mresponses[url].response_code == 403
            plugin_list << url.split('/')[-1] # Add Plugin to the Keepers list :)
          end
        end
        break if plugins.size == 0
      end
      if plugin_list.size > 0 # If we found anything, report it to user ;)
        if verbose
          print_good("Found #{plugin_list.uniq.size} Plugins: ")
          plugin_list.uniq.each do |p| 
            # Check and see if we can find out the specific plugin version info too
            res = @http.get(site.sub(/\/$/, '') + "/wp-content/plugins/#{p}/readme.txt")
            if res[0] =~ /^Stable tag: (.+)\s+/i
              print_line("   #{p}, version: #{$1.strip.chomp}")
            else
              print_line("   #{p}")
            end
          end
        end
        return plugin_list.uniq
      end
      return nil
    else
      print_error("Unable to find #{plist}!") if verbose
      print_error("Can't run forceful plugin enumeration without it.....") if verbose
      return nil
    end
  end

  # WP Theme Enumerator
  # Checks for Indexed Themes Directory
  # Simply calls out the themes found...
  def wp_theme_enumerator(site=@site, verbose=true)
    @wp_paths.each do |p|
      theme_dir = site.sub(/\/$/, '') + p + '/wp-content/themes/'
      res = @http.get(theme_dir)
      if res[0] =~ /<title>Index of.+\/wp-content\/themes<\/title>|<h1>Index of.+\/wp-content\/themes<\/h1>/i
        t1 = res[0].scan(/href="(.+)\/">?[a-z]/)
        t2 = res[0].scan(/href="(.+)\/"> ?[a-z]/)
        themez = t1 + t2
        bad=['foo'] # Defaults and/or useless for our purposes...
        themes=[]
        themez.each {|t| themes << t unless themes.include?(t) or bad.include?(t) } 
        print_good("Themes Directory Located: #{p}/wp-content/themes/") if verbose
        print_good("Themes Found: ") if verbose
        if verbose
          themes.uniq.each do |p|
            puts "   [".light_green + "+".white + "] ".light_green + "#{p[0]}".white
          end
        end
        return themes.uniq
      end
    end
    return nil 
  end

  # Forcefull Theme Check
  # We load the wp_themes_full.txt list and check to see what seems to exist
  # Returns array of theme names found to be installed, or nil
  def wp_theme_forceful_enumerator(tlist=nil, site=@site, verbose=true)
    if tlist.nil?
      tlist = HOME + 'fuzz/wp_themes.txt'
    end
    if File.exists?(tlist)
      themes_list = []
      themes = File.open(tlist).readlines  # Load our Plugins list as array & Create the Stack
      print_status("Testing #{themes.size} possible plugins, hang tight....")
      print_status("Running in #{themes.size / 2500} chunks due to size of plugins list....") if themes.size > 2500
      # While we have a stack, loop and run Curl multi Calls in chunks
      # I get crappy results when I send 40K at once, who knew?
      # This seems to resolve the issue and maintain reasonable speed...
      while themes.size > 0
        queue=[]
        test_urls = []
        num = 2500
        if themes.size < 2500
          num = themes.size
        end
        (0..num.to_i).each {|x| z=themes.pop; queue << z.chomp unless z.nil? or z.strip == ''  } # Seed our Queue & Shrink the Stack Down
        queue.each { |theme_name| test_urls << site.sub(/\/$/, '') + "/wp-content/themes/#{theme_name.strip.chomp}/" } # Seed our plugin urls
        $config['HTTP']['PROGRESS'] = true        # Enable progressbar
        mresponses = @http.multi_get(test_urls)    # Curl Multi Mode Makes the Checks Faster
        print "\r"
        $config['HTTP']['PROGRESS'] = false       # Disable progressbar
        test_urls.each do |url| # Check results...
          if mresponses[url].response_code == 200 or mresponses[url].response_code == 403
            themes_list << url.split('/')[-1] # Add Plugin to the Keepers list :)
          end
        end
        break if themes.size == 0
      end
      if themes_list.uniq.size > 0 # If we found anything, report it to user ;)
        if verbose
          print_good("Found #{themes_list.uniq.size} Themes: ")
          themes_list.uniq.each do |t| 
            # Check and see if we can find out the specific plugin version info too
            res = @http.get(site.sub(/\/$/, '') + "/wp-content/themes/#{t}/style.css")
            if res[0] =~ /^Version: (.+)\s+/i
              print_line("   #{t}, version: #{$1.strip.chomp}")
            else
              print_line("   #{t}")
            end
          end
        end
        return themes_list
      end
      return nil
    else
      print_error("Unable to find #{tlist}!") if verbose
      print_error("Can't run forceful theme enumeration without it.....") if verbose
      return nil
    end
  end

  # Quick Dirbuster Style Check
  # Looks for common backup & configuration files
  def wp_backup_configs_check(site=@site, verbose=true)
    found = []
    test_urls = []
    dirs = [ '', '/wp-content', '/wp-content/includes', '/backup', '/backups' ]
    juicy = [ '/wp-config.php', '/wp-config.php~', '/#wp-config.php#', '/wp-config.php.save', '/wp-config.php.swp', '/wp-config.php.swo', '/wp-config.php_bak', '/wp-config.bak', '/wp-config.php.bak', '/wp-config.save', '/wp-config.old', '/wp-config.php.old', '/wp-config.php.orig', '/wp-config.orig', '/wp-config.php.original', '/wp-config.original', '/wp-config.txt', '/wp-config.txt.tar.gz', '/wp-config.txt.tgz', '/wp-config.php.tar.gz', '/wp-config.php.tgz', '/wp.sql', '/db.sql', '/database.sql', '/backup.sql', '/wp_users.sql' ]
    dirs.each do |d|
      juicy.each { |j| test_urls << site.sub(/\/$/, '') + d + j }
    end
    $config['HTTP']['PROGRESS'] = true        # Enable progressbar
    mresponses = @http.multi_get(test_urls)    # Curl Multi Mode Makes the Checks Faster
    $config['HTTP']['PROGRESS'] = false       # Disable progressbar
    test_urls.each do |url|                   # Check results...
      if mresponses[url].response_code == 200
        found << url                          # Found One!
      end
    end
    puts
    if found.uniq.size > 0
      if verbose
        print_good("Found Possible Config Backups!")
        found.each do |url|
          print_line("   #{url}")
        end
      end
      return found
    end
    print_error("No Backups Found!")
    return nil
  end

  # Forceful Check for Known TimThumb.php instances
  # File is known to be vulnerable to remote command execution
  # Returns array of found files, or nil
  def wp_timthumbs_check(thumbs_list=nil, site=@site, verbose=true)
    found = []
    test_urls = []
    if thumbs_list.nil?
      thumbs_list = HOME + 'fuzz/wp_timthumbs.txt'
    end
    if File.exists?(thumbs_list.strip.chomp)
      thumbz = File.open(thumbs_list.strip.chomp).readlines
      thumbz.each { |thumb| test_urls << site.sub(/\/$/, '') + thumb.strip.chomp }
      $config['HTTP']['PROGRESS'] = true        # Enable progressbar
      mresponses = @http.multi_get(test_urls)    # Curl Multi Mode Makes the Checks Faster
      $config['HTTP']['PROGRESS'] = false       # Disable progressbar
      test_urls.each do |url|                   # Check results...
        found=false
        # Check responses
        if mresponses[url].response_code == 400 and mresponses[url].body_str =~ /no image specified/i
          found=true
          found << url unless found.include?(url)
        end
        if mresponses[url].body_str =~ /TimThumb version\s*: ([^<]+)/i
          found=true
          version = $1.strip.chomp
          found << url unless found.include?(url)
        end
      end
    else
      puts
      print_error("Unable to load #{thumbs_list.strip.chomp}!")
      print_error("Please check path or permissions and try again....\n\n")
    end
    return nil
  end

  # Try to enumerate WP Users
  # Leverages the /author?=[id] trick
  # Helpful if you want to bruteforce login later
  def wp_users_check(site=@site, verbose=true)
    usernames=[]
    test_urls = []
    (0..10).each {|x| test_urls << site.sub(/\/$/, '') + "/?author=#{x}" }
    $config['HTTP']['PROGRESS'] = true        # Enable progressbar
    mresponses = @http.multi_get(test_urls)    # Curl Multi Mode Makes the Checks Faster
    $config['HTTP']['PROGRESS'] = false       # Disable progressbar
    test_urls.each do |url|                   # Check results...
      # Check Location Header on 302 for Username...
      if mresponses[url].response_code == 301 or mresponses[url].response_code == 302
        mresponses[url].header_str.split("\n").each do |hline|
          header_name = hline.split(':')[0]
          header_value = hline.split(':')[1..-1].join('/').sub("\r", '')
          if header_name =~ /Location/i
            user = header_value.split('/')[-1].to_s.strip.chomp
            usernames << user unless usernames.include?(user)
          end
        end
      end
      # Check Body for Username Info...
      if mresponses[url].body_str =~ /^<link rel="alternate" type="application\/rss\+xml" title=".+ &raquo; .+" href=".+\/author\/(.+)\/feed\//
        user = $1.strip.chomp
        usernames << user unless usernames.include?(user)
      end
    end
    if usernames.uniq.size > 0
      if verbose
        print_good("Found #{usernames.uniq.size} users: ")
        usernames.uniq.each {|u| print_line("   #{u.strip.chomp}") }
      end
      return usernames
    end
    return nil 
  end

  # Check if /xmlrpc.php is present
  def wp_xmlrpc_check(site=@site, verbose=true)
    xmlrpc_file = site.sub(/\/$/, '') + '/xmlrpc.php'
    res = @http.get(xmlrpc_file)
    if res[1] == 200 or res[1] == 403
      print_good("XML-RPC: #{xmlrpc_file}") if verbose
      return true
    else
      print_error("No XML-RPC Found!")
    end
    return false
  end

  # Attempt to Login to Exposed XML-RPC Interface
  # Returns true on success, or false if not
  def wp_xmlrpc_login(user='admin', password='admin123', path='/xmlrpc.php', site=@site, verbose=true)
    # Need to redo without rubypress dependency....
    return
  end

  # XML-RPC Interface Login Bruter
  def wp_xmlrpc_login_brute(user='admin', wordlist=nil, path='/xmlrpc.php', site=@site)
    if wordlist.nil?
      wordlist = HOME + 'fuzz/wordlists/500-worst-passwords.txt'
    end
    credz={}
    if File.exists?(wordlist.strip.chomp)
      passwords=File.open(wordlist.strip.chomp).readlines
      while passwords.size > 0
        pass = passwords.pop

        # Add Threading here?
        if wp_xmlrpc_login(user, pass.chomp, path, site, false)
          print_good("Successfully Authenticated to XML-RPC Interface!")
          print_good("Target: #{site.sub(/\/$/, '') + path}")
          print_good("User: #{user}")
          print_good("Pass: #{pass.chomp}")
          puts
          break # We win
        end

        break if passwords.size == 0
      end
    else
      puts
      print_error("Unable to load wordlist!")
      print_error("Check path or permissions and try again....\n\n")
      return nil
    end
  end

  # WP Login Check
  # Check if credentials work or not
  # Returns true on success, false otherwise
  def wp_login_check(user='admin', pass='password', path=nil, site=@site, verbose=true)
    if path.nil?
      path = '/wp-login.php'
    end
    if $config['HTTP']['HTTP_HEADERS_ADD']
      flip=false
    else
      $config['HTTP']['HTTP_HEADERS_ADD']=true
      flip=true
    end
    $config['HTTP']['HTTP_HEADERS'].store('Cookie', 'wordpress_test_cookie=WP+Cookie+check')
    redirect = site.sub(/\/$/, '') + '/wp-admin/'
    test_url = site.sub(/\/$/, '') + path
    test_data = "log=#{user}&pwd=#{pass}&wp-submit=Log+In&redirect_to=#{redirect.urienc}&testcookie=1"
    res = @http.post(test_url, test_data)
    if res[1] == 301 or res[1] == 302
      auth_cookies=[]
      res[3].split("\n").each do |line|
        header_name = line.split(':')[0]
        header_value = line.split(':')[1..-1].join('/').sub("\r", '')
        if line =~ /Set-cookie: (.+);/i
          auth_cookies << $1.chomp
        end
        if header_name =~ /Location/i
          landing_page = header_value.split('/')[-1].to_s.strip.chomp
          if landing_page =~ /wp-admin/i
            print_good("Successfully authenticated to WordPress!")
            print_good("Target: #{site.sub(/\/$/, '') + path}")
            print_good("User: #{user}")
            print_good("Pass: #{pass}")
            if auth_cookies.size > 0
              print_good("Authorized Cookies: ")
              auth_cookies.each {|c| print_line("   #{c}") }
            end
            puts
            $config['HTTP']['HTTP_HEADERS'].delete('Cookie')
            if flip
              $config['HTTP']['HTTP_HEADERS_ADD'] = false
            end
            return true
          end
        end
      end
    end
    print_error("Failed to authenticate with provided credentials!") if verbose
    $config['HTTP']['HTTP_HEADERS'].delete('Cookie')
    if flip
      $config['HTTP']['HTTP_HEADERS_ADD'] = false
    end
    return nil
  end

  # Simple WordPress Login Bruter
  # Pass in username and Dictionary to use (& custom path if needed)
  # Will loop through list and try all possibilities
  # Leverages Curl Multi for fast POST requests
  # Sends in chunks of 10 at a time, checks results on receipt of all responses
  # Displays results when found and exits request loop
  # Nothing returned, just a visual thing here....
  def wp_login_bruter(user='admin', wordlist=nil, path='/wp-login.php', site=@site)
    if File.exists?(wordlist.strip.chomp)
      if path.nil?
        path = '/wp-login.php'
      end
      if $config['HTTP']['HTTP_HEADERS_ADD']
        flip=false
      else
        $config['HTTP']['HTTP_HEADERS_ADD']=true
        flip=true
      end
      url = site.sub(/\/$/, '') + path
      redirect = site.sub(/\/$/, '') + '/wp-admin/'
      $config['HTTP']['HTTP_HEADERS'].store('Cookie', 'wordpress_test_cookie=WP+Cookie+check')
      passwords = File.open(wordlist.strip.chomp).readlines
      print_status("Loaded #{passwords.size} passwords from #{wordlist.strip.chomp}!")
      print_status("Launching wp-login bruter, hang tight....")

      # Build out our easy handle options to prep for multi...
      # Done everything I can to keep things respecting the config file settings!
      multi_options = {:pipeline => true}
      easy_options  = { :ssl_verify_peer => false, :max_redirects => 3, :timeout => $config['HTTP']['TIMEOUT']}

      # Set Proxy Connection Details if needed
      if $config['HTTP']['PROXY']
        easy_options.store(:proxy, "#{$config['HTTP']['PROXY_IP']}:#{$config['HTTP']['PROXY_PORT']}")

        if $config['HTTP']['TOR_PROXY']
          easy_options.store(:proxy_type, 'CURLPROXY_SOCKS5') # Change proxy type to Socks5 for ToR use
        end
        if $config['HTTP']['PROXY_AUTH']
          easy_options.store(:proxyuserpwd, "#{$config['HTTP']['PROXY_USER']}:#{$config['HTTP']['PROXY_PASS']}")
        end
      end

      # Set HTTP Authentication Details if needed
      if $config['HTTP']['HTTP_AUTH']
        easy_options.store(:http_auth_types, :basic)
        easy_options.store(:userpwd, "#{$config['HTTP']['HTTP_AUTH_USER']}:#{$config['HTTP']['HTTP_AUTH_PASS']}")
      end

      headers = {}
      # Add custom referrer if needed
      if $config['HTTP']['REF']
        headers.store('Referer', $config['HTTP']['REFERER'])
      end

      # Add custom headers as needed
      if $config['HTTP']['HTTP_HEADERS_ADD']
        $config['HTTP']['HTTP_HEADERS'].each do |k, v|
          headers.store("#{k}", "#{v}")
        end
      end

      # Add custom cookies if needed
      if $config['HTTP']['COOKIESUPPORT']
        easy_options.store(:cookiefile, $config['HTTP']['COOKIEFILE'])
      end

      # Set User-Agent to default or whatever was selected
      headers.store('User-Agent', $config['HTTP']['HTTP_USER_AGENT'])

      # Now add all the headers we needed
      easy_options.store(:headers, headers)

      auth_cookies=[]
      while passwords.size > 0
        break if auth_cookies.size > 0
        # Now Build out our URL's Array based on number of passwords provided in wordlist
        test_urls=[]
        if passwords.size < 10
          num = passwords.size
        else
          num = 9 # Zero Index
        end
        (0..num.to_i).each {|x| 
          test_urls << { :url => url, :post_fields => { 'log' => user, 'pwd' => passwords.shuffle.pop.chomp, 'wp-submit' => 'Log+In', 'redirect' => redirect.urienc, 'testcookie' => 1 } }
        }
        # Put it all together & Run via Curl Multi Calls
        # This helps to keep things quick
        Curl::Multi.post(test_urls, easy_options, multi_options) do |easy|
          if easy.post_body =~ /&pwd=(.+)&wp-submit/
            pass = $1
          end
          if easy.response_code == 301 or easy.response_code == 302
            easy.header_str.split("\n").each do |line|
              header_name = line.split(':')[0]
              header_value = line.split(':')[1..-1].join('/').sub("\r", '')
              if line =~ /Set-cookie: (.+);/i
                auth_cookies << $1.chomp
              end
              if header_name =~ /Location/i
                landing_page = header_value.split('/')[-1].to_s.strip.chomp
                if landing_page =~ /wp-admin/i
                  print_good("Successfully authenticated to WordPress!")
                  print_good("Target: #{site.sub(/\/$/, '') + path}")
                  print_good("User: #{user}")
                  print_good("Pass: #{pass}")
                  if auth_cookies.size > 0
                    print_good("Authorized Cookies: ")
                    auth_cookies.each {|c| print_line("   #{c}") }
                  end
                  puts
                end
              end
            end
          end
          break if auth_cookies.size > 0 or passwords.size == 0
        end
      end
      $config['HTTP']['HTTP_HEADERS'].delete('Cookie')
      if flip
        $config['HTTP']['HTTP_HEADERS_ADD'] = false
      end
    else
      puts
      print_error("Unable to load wordlist!")
      print_error("Check path or permissions and try again....\n\n")
    end
  end
end
