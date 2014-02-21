# Various functions to check for FCKeditor
# Widely used and long list of known vulnerabilities over the years
# Add functions to class as you can to make available for checks and active audits

class FCKEditor
  def initialize(link='http://somesite.com/')
    @url=link
    @site = link.chomp.sub('http://', '').sub('https://', '').sub('www.', '').sub(/\/$/, '')
    foo=@site.split('/')
    if foo.size > 1
      @site=foo[0]                    # Host or target domain
    end
    @base="htpp://#{@site}"
    @http=EasyCurb.new
  end

  # Check for known files left behind following installation and upgrades
  # _whatsnew.html will give us the current version in use if found
  # _whatsnew_history.html will point to the last version known to be in use
  # Returns the version information or nil
  def version_check(site=@base, verbose=false)
    print_status("Running FCKEditor version check against #{site}/...") if verbose
    # Common prefixed directories for blind enumerations
    prefixes = [ '/assets', '/libraries', '/inc', '/includes', '/js', '/new', '/applets', '/packages', '/admin', '/templates' ]
    # Our Test Pages array
    test_pages = [ 
      '/fckeditor/_whatsnew.html',
      '/FCKeditor/_whatsnew.html',
      '/fckeditor/editor/dialog/fck_about.html',
      '/FCKeditor/editor/dialog/fck_about.html',
      '/CFIDE/scripts/ajax/FCKeditor/editor/dialog/fck_about.html',
      '/fckeditor/_whatsnew_history.html'
    ]
    links=[]
    prefixes.each do |p|
      pre = site + p
      test_pages.each do |q|
        links << pre + q unless links.include?(pre + q)
        links << site + q unless links.include?(site + q)
      end
    end
    links.uniq!
    # Check each link for version info
    print_status("Checking for FCKeditor version info....") if verbose
    while links.size > 0
      link = links.pop
      res = @http.get(link.strip.chomp)
      if link =~ /_whatsnew_history.html/
        # Version info points to previou version known to be installed before last update
        if res[0] =~ /<H3>\s+Version (.+)<\/H3>/i
          v = "Version: #{$1}"
          puts "   [".light_green + "+".white + "] ".light_green + "Previous FCKEditor #{v}".white if verbose
        end
      else
        if res[0] =~ /<H3>\s+Version (.+)<\/H3>/i
          version = "Version: #{$1}"
          puts "   [".light_green + "+".white + "] ".light_green + "Confirmed FCKEditor #{version}".white if verbose
          break
        elsif res[0] =~ /<span .+">version<\/span>\s+<br>\s+<b>(.+)<\/b><\/td>/
          version = "Version: #{$1}"
          puts "   [".light_green + "+".white + "] ".light_green + "Confirmed FCKEditor #{version}".white if verbose
            break
        elsif res[0] =~ /<br \/>\s+<b>(.+)<\/b><br \/>/
          vers=$1
          if res[0] =~ /\s+(.+)<\/td>/
            build=$1
          end
          if vers and build
            puts "   [".light_green + "+".white + "] ".light_green + "Confirmed Version: #{vers}, #{build}".white if verbose
            version = "Version: #{vers}, #{build}"
            break
          end
        end
      end
      break if links.empty?
    end
    if version.nil?
      print_error("Failed to find anything usable...") if verbose
      return nil
    end
    return version
  end

  # Check for the existance of known uploaders or connector scripts
  # Returns array of files found or nil
  def uploader_file_check(site=@base, verbose=true, veryverbose=false)
    prefixes = [ '/libraries', '/inc', '/includes', '/js', '/new', '/applets', '/packages', '/admin', '/templates' ]
    print_status("Checking for known FCKEditor uploaders...")
    test_pages = [ '/fckeditor/editor/filemanager/upload/test.html', '/FCKeditor/editor/filemanager/upload/test.html', '/fckeditor/editor/filemanager/browser/default/connectors/php/connector.php', '/FCKeditor/editor/filemanager/browser/default/connectors/php/connector.php', '/fckeditor/editor/filemanager/browser/default/connectors/asp/connector.asp', '/FCKeditor/editor/filemanager/browser/default/connectors/asp/connector.asp', '/fckeditor/editor/filemanager/browser/default/connectors/aspx/connector.aspx', '/FCKeditor/editor/filemanager/browser/default/connectors/aspx/connector.aspx', '/fckeditor/editor/filemanager/browser/default/connectors/cfm/connector.cfm', '/FCKeditor/editor/filemanager/browser/default/connectors/cfm/connector.cfm', '/fckeditor/editor/filemanager/browser/default/connectors/perl/connector.cgi', '/FCKeditor/editor/filemanager/browser/default/connectors/perl/connector.cgi', '/ckfinder/ckfinder.html', '/CKfinder/ckfinder.html', '/CFIDE/scripts/ajax/FCKeditor/editor/filemanager/connectors/cfm/upload.cfm', '/CFIDE/scripts/ajax/FCKeditor/editor/filemanager/connectors/asp/upload.asp', '/CFIDE/scripts/ajax/FCKeditor/editor/filemanager/connectors/perl/upload.cgi' ]
    links=[]
    prefixes.each do |p|
      pre = site + p
      test_pages.each do |q|
        links << pre + q unless links.include?(pre + q)
        links << site + q unless links.include?(site + q)
      end
    end
    links.shuffle.uniq!
    found=[]
    disabled=[]
    links.each do |link|
      print_status("Checking #{link.sub(site, '')}") if verbose and veryverbose
      res = @http.get(link)
      if res[0] =~ /This connector is disabled/i
        disabled << link
        next
      elsif res[1] == 200 and not res[0] =~ /This connector is disabled/i
        found << link
      end
    end
    if found.size > 0
       puts "   [".light_green + "-".white + "] ".light_green + "FCKEditor Uploader File(s) Found!".white if verbose
      found.each {|link| puts "      [".light_green + "+".white + "] ".light_green + "#{link}".white if verbose }
      if disabled.size > 0
        puts if verbose
        puts "   [".light_yellow + "-".white + "] ".light_yellow + "Disabled FCKEditor File(s) Found!".white if verbose
        disabled.each {|link| puts "      [".light_yellow + "+".white + "] ".light_yellow + "#{link}".white if verbose }
      end
      return found
    else
      puts "   [".light_red + "-".white + "] ".light_red + "NO FCKEditor uploaders found!".white if disabled.empty? and verbose
      puts "   [".light_red + "-".white + "] ".light_red + "NO usable FCKEditor uploaders found!".white if disabled.size > 0 and verbose
      return nil
    end
  end
end
