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
    http=EasyCurb.new
    @wp_paths.each do |p|
      link = site.sub(/\/$/, '') + p
      link += '/' if p == ''
      res = http.get(site)
      if res[0] =~ /<meta name="generator" content="(WordPress \d+.\d+?.?\d+)" \/>/i
        wp_version = $1.chomp
        print_good("Generator Tag found!")
        print_good("Version: #{wp_version}") if verbose
        return wp_version
      end
    end
    return nil
  end

  # WordPress Version Identification via default INSTALL.html file
  # Returns version on success, nil otherwise...
  def wp_install_version_check(site=@site, verbose=true)
    http=EasyCurb.new
    @wp_paths.each do |p|
      installer = site.sub(/\/$/, '') + p + '/INSTALL.html'
      res = http.get(installer)
      if res[0] =~ /for (WordPress \d+.\d+?.?\d+)<\/title>/i
        wp_version = $1.chomp
        print_good("#{p}/INSTALL.html Found!") if verbose
        print_good("Version: #{wp_version}") if verbose
        return wp_version
      elsif res[0] =~ /<br \/> Version (.*)/
        wp_version = $1.chomp
        print_good("#{p}/INSTALL.html Found!") if verbose
        print_good("Version: #{wp_version}") if verbose
        return wp_version
      end
    end
    print_error("Unable to locate default INSTALL.html file....") if verbose
    return nil
  end

  # WordPress Version Identification via default readme.html file
  # Returns version on success, nil otherwise...
  def wp_readme_version_check(site=@site, verbose=true)
    http=EasyCurb.new
    @wp_paths.each do |p|
      readme = site.sub(/\/$/, '') + p + '/readme.html'
      res = http.get(readme)
      if res[0] =~ /for (WordPress \d+.\d+?.?\d+)<\/title>/i
        wp_version = $1.chomp
        print_good("#{p}/readme.html Found!") if verbose
        print_good("Version: #{wp_version}") if verbose
        return wp_version
      elsif res[0] =~ /<br \/> Version (.*)/
        wp_version = $1.chomp
        print_good("#{p}/readme.html Found!") if verbose
        print_good("Version: #{wp_version}") if verbose
        return wp_version
      end
    end
    print_error("Unable to locate default readme.html file....") if verbose
    return nil
  end

  # WordPress Version Identification via RSS Feed's generator tag
  # Returns version on success, nil otherwise...
  def wp_rss_version_check(site=@site, verbose=true)
    http=EasyCurb.new
    @wp_paths.each do |p|
      feed = site.sub(/\/$/, '') + p + '/feed/'
      res = http.get(feed)
      if res[0] =~ /<generator>(.+)<\/generator>/i
        wp_version = $1.chomp.sub('http://wordpress.org/?v=', '')
        print_good("#{p}/feed/ Found!") if verbose
        print_good("Version: #{wp_version}") if verbose
        return wp_version
      end
    end
    print_error("Unable to locate generator tag in RSS feed....") if verbose
    return nil
  end

  # WP Plugins Enumerator
  # Checks for Indexed Plugins Directory
  # Simply calls out the plugins found...
  def wp_plugin_enumerator(site=@site, verbose=true)
    http=EasyCurb.new
    @wp_paths.each do |p|
      plugins_dir = site.sub(/\/$/, '') + p + '/wp-content/plugins/'
      res = http.get(plugins_dir)
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
          plugins.each do |p|
            puts "   [".light_green + "+".white + "] ".light_green + "#{p[0]}".white
          end
        end
        ##########################################################
        # Add static array check for known vuln plugins here.....
        # If found, add to list (call out special vuln mesg?)....
        ##########################################################
        return plugins
      end
    end
    return nil 
  end

  # WP Theme Enumerator
  # Checks for Indexed Themes Directory
  # Simply calls out the themes found...
  def wp_theme_enumerator(site=@site, verbose=true)
    http=EasyCurb.new
    @wp_paths.each do |p|
      theme_dir = site.sub(/\/$/, '') + p + '/wp-content/themes/'
      res = http.get(theme_dir)
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
          themes.each do |p|
            puts "   [".light_green + "+".white + "] ".light_green + "#{p[0]}".white
          end
        end
        ##########################################################
        # Add static array check for known vuln themes here.....
        # If found, add to list (call out special vuln mesg?)....
        ##########################################################
        return themes
      end
    end
    return nil 
  end
end
