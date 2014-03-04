# This is our Crawler Class
# This should house anything related to Site Crawling for Links

# First we mod the Anemone class so HTTP Auth is supported!
# Big Thanks to Sergio Tulentsev for his post on StackOverflow
# Code borrowed from there, wish i thought of it on my own :p
# http://stackoverflow.com/questions/16846089/http-basic-authentication-with-anemone-web-spider
module Anemone
  class HTTP
    def get_response(url, referer = nil)
      full_path = url.query.nil? ? url.path : "#{url.path}?#{url.query}"

      opts = {}
      opts['User-Agent'] = $config['HTTP']['HTTP_USER_AGENT'] if $config['HTTP']['HTTP_USER_AGENT']
      opts['Referer'] = $config['HTTP']['REFERER'] if $config['HTTP']['REF']
      opts['Cookie'] = @cookie_store.to_s unless @cookie_store.empty? || (!accept_cookies? && @opts[:cookies].nil?)

      retries = 0
      begin
        start = Time.now()
        # format request
        req = Net::HTTP::Get.new(full_path, opts)
        response = connection(url).request(req)
        finish = Time.now()
        ############# TWEAK START HERE ################
        # HTTP Basic authentication Activation
        if $config['HTTP']['HTTP_AUTH'] # boolean to activate or disable auth
          req.basic_auth $config['HTTP']['HTTP_AUTH_USER'], $config['HTTP']['HTTP_AUTH_PASS']
        end
        ############# TWEAK END HERE ##################
        response_time = ((finish - start) * 1000).round
        @cookie_store.merge!(response['Set-Cookie']) if accept_cookies?
        return response, response_time
      rescue Timeout::Error, Net::HTTPBadResponse, EOFError => e
        puts e.inspect if verbose?
        refresh_connection(url)
        retries += 1
        retry unless retries > 3
      end
    end
  end
end

# Our actual crawler class
# wraps Anemone gem for core functionality
class Crawler
  def initialize(url='http://site.com/', link_limit=0, depth_limit=0, thread_count=4, obey_robots=false)
    @url=url                          # Target URL
    @limit=link_limit                 # Links per page, 0=none
    if depth_limit.to_i == 0
      @depth_limit = false            # No depth limit
    else
      @depth_limit = depth_limit.to_i # Set defined Depth limit for crawl
    end
    @obey_robots=obey_robots          # Obey robots.txt or not for crawl
    @thread_count=thread_count        # Crawler threads, default works fine and is considered safe
    @site = url.chomp.sub('http://', '').sub('https://', '').sub('www.', '').sub(/\/$/, '')
    foo=@site.split('/')
    if foo.size > 1
      @site=foo[0]                    # Host or target domain
    end
    @crawl_cookies={}
    if File.exists?($config['CRAWLER']['C_COOKIES'])
      File.open($config['CRAWLER']['C_COOKIES']).readlines.each do |line|
        key = line.split(':')[0]
        value = line.split(':')[1]
        @crawl_cookies.store(key, value)
      end
    end
    @crawl_cookies=nil if not @crawl_cookies.size > 0
    Dir.mkdir(RESULTS + 'recon/') unless File.exists?(RESULTS + 'recon/') and File.directory?(RESULTS + 'recon/')
    # MongoDB Setup
    if $config['CRAWLER']['MONGO_SUPPORT']
      begin
        @mongodb = Mongo::MongoClient.new($config['CRAWLER']['MONGO_HOST'], $config['CRAWLER']['MONGO_PORT'].to_i).db($config['CRAWLER']['MONGO_DB'])
#      @mongodb = MongoClient.new("localhost", 27017).db('makeshift')authenticate('my_user_name', 'my_password')
        @mongodb_collection = @mongodb["#{$config['CRAWLER']['MONGO_COLLECTION']}"]
        @mongodb_collection.remove # Erase any existing data in collection for fresh start
        print_good("MongoDB connection established!")
      rescue
        $config['CRAWLER']['MONGO_SUPPORT'] = false
        print_error("Problem connecting MongoDB!")
        print_error("Have to continue without DB support now as a result...")
      end
    end
  end

  # Do the actual site crawling to gather links
  # Starts at base link provided and enumerates links until no more can be found
  # It parses source code for reference links of various kinds to identify links
  def crawl_site
    trap("SIGINT") {
      print_error("CTRL+C! Returning to Previous Menu....")
      return
    }
    cls
    banner
    @outdir = "#{RESULTS}recon/#{@site}/"
    @outfile="#{@outdir}crawler.links"
    forms_file="#{@outdir}forms_found.txt"
    cookies_file="#{@outdir}set_cookies.txt"
    Dir.mkdir(@outdir) unless File.exists?(@outdir) and File.directory?(@outdir)
    print_status("Starting Crawler Session.......")
    print_status("###############################")
    print_good("Host: #{@site}")
    print_good("Crawling from: #{@url}")
    print_good("User-Agent:\n#{$user_agent}")
    if @limit == 0
      print_good("Link Limit: None")
    else
      print_good("Link Limit: #{@limit}")
    end
    print_good("Thread Count: #{@thread_count}")
    print_status("###############################")
    puts
    @emails=[]
    @cookiez=[]
    @key_headerz={}
    @meta_keywords=[]
    @phpbb_forum = 'N/A'
    f = File.open(@outfile, "w+")
    ff = File.open(forms_file, "w+")
    z = File.open(cookies_file, 'w+')
    emails_regex = /[\w.!#\$%+-]+@[\w-]+(?:\.[\w-]+)+/ # Easy regex to extract
    while(true)
      # Launch our actual Crawler with provided options
      Anemone.crawl(@url.sub(/\/$/, ''), { :threads => @thread_count.to_i, :obey_robots_txt => @obey_robots, :cookies => @crawl_cookies, :accept_cookies => $config['CRAWLER']['ACCEPT_COOKIES'], :depth_limit => @depth_limit, :user_agent => $config['HTTP']['HTTP_USER_AGENT'], :proxy_host => $config['HTTP']['PROXY_IP'], :proxy_port => $config['HTTP']['PROXY_PORT'] }) do |anemone|

        # Storage for headers from active page request
        key_headerz={}

        # MongoDB Support if requested
        if $config['CRAWLER']['MONGO_SUPPORT']
          anemone.storage = Anemone::Storage.MongoDB
        end

        # Skip links matching the user defined regex
        regx = $config['CRAWLER']['DONT_CRAWL'].source
        anemone.skip_links_like /#{regx}/

        # Parse the page object to try and extract additional links for active crawling queue
        # Returns array of links to crawl per page
        # NOTE: The links you give back must be URL objects and not String objects!
	###############
	# Old
	#        if @limit.to_i != 0
	#          anemone.focus_crawl { |page| page.links.slice(0..@limit.to_i) } # Limit links per page if requested
	#        end
	###############
        anemone.focus_crawl do |page|
          links_to_follow=[]

          # Add any clearly defined HREF links
          page.links.each { |link| 
            links_to_follow << link
          }

          # Do some double checking to make sure we dont miss any though
          if not page.doc.nil? and not page.doc.search("//a[@href]").nil?
            page.doc.search("//a[@href]").each do |a|
              u = a['href']
              next if u.nil? or u.empty?
              u = page.to_absolute(u) rescue next
              chk=URI(u)
              links_to_follow << chk if chk.host == @site and not links_to_follow.include?(u)
            end
          end

          # Add any available Image SRC Links
          if not page.doc.nil? and not page.doc.search("//img[@src]").nil?
            page.doc.search("//img[@src]").each do |a|
              u = a['src']
              next if u.nil? or u.empty?
              if not u =~ /^http/
                u = page.to_absolute(u)
              end
              chk=URI(u)
              links_to_follow << chk if chk.host == @site and not links_to_follow.include?(u)
            end
          end

          # Add any available iframe SRC Links
          if not page.doc.nil? and not page.doc.search("//iframe[@src]").nil?
            page.doc.search("//iframe[@src]").each do |a|
              u = a['src']
              next if u.nil? or u.empty?
              if not u =~ /^http/
                u = page.to_absolute(u)
              end
              chk=URI(u)
              links_to_follow << chk if chk.host == @site and not links_to_follow.include?(u)
            end
          end

          # Grab any available Form Action Links
          if not page.doc.nil? and page.body =~ /<form.+action=([\\'"].+[\\'"]).+?>/i
            action_formz = page.body.match(/<form.+action=([\\'"].+[\\'"]).+?>/i)
            action_formz.to_a.each do |f_str|
              if f_str =~ /action=[\\'"](.+)[\\'"]?/i
                u = $1.chomp.split(' ')[0].sub(/[\\'"]$/, '')
                if not u =~ /^http/i
                  u = page.to_absolute(u)
                end
                chk=URI(u)
                links_to_follow << chk if chk.host == @site and not links_to_follow.include?(u)
              end
            end
          end

          # Redirect URLs
          if page.redirect? and not page.headers['location'].nil?
            u = page.headers['location'][0].to_s
            chk=URI(u)
            links_to_follow << chk if chk.host == @site and not links_to_follow.include?(u)
          end

          # Remove Duplicate Links
          links_to_follow = links_to_follow.uniq

          # Finally, we return our array of links that we actually want to follow for this page
          # Limit the number of links per page if requested/needed
          if @limit.to_i != 0
            links_to_follow.slice(0..@limit.to_i)
          else
            links_to_follow
          end
        end

        # Now we pull out everything we can from each page as its visited
        # Call out important stuff in terminal, log it all to files and db if selected
        # Parse it when done
        anemone.on_every_page do |page|
          url = page.url.to_s
          depth = page.depth.to_s || 'N/A'
          code = page.code.to_s || 'N/A'
          time = page.response_time.to_s || 'N/A'
          if not page.body.nil? and not page.body == ''
            body = Nokogiri::HTML(page.body)
            size = page.body.size
          else
            body = 'N/A'
            size = 'N/A'
          end
          if not page.headers['content-length'].nil? and page.headers['content-length'].size > 0
            content_length = page.headers['content-length'][0]
            puts "   [".light_blue + "-".white + "] ".light_blue + "Content-Length: #{page.headers['content-length'][0]}".white
          else
            content_length = 'N/A'
          end
          if page.redirect_to.nil? or page.redirect_to.to_s == ''
            redirect_to = 'N/A'
          else
            redirect_to = page.redirect_to
          end

          # Capture Page title & Meta Data info
          # This might be handy somewhere later for post analysis or SEO type review...
          if page =~ /<title>(.*)<\/title>/
            page_title=$1.to_s.strip.chomp.encode('UTF-8')
          else
            page_title='N/A'
          end
          begin
            page_description=page.at('meta[name="description"]')['content'].encode('UTF-8')
          rescue
            page_description='N/A'
          end
          begin
            page_keywords=page.at('meta[name="keywords"]')['content'].encode('UTF-8')
           if not @meta_keywords.include?(page_keywords)
             @meta_keywords << page_keywords
           end
          rescue
            page_keywords='N/A'
          end
          begin
            page_generator=page.at("meta[name='generator']")['content'].encode('UTF-8')
          rescue
            page_generator='N/A'
          end
          begin
            page_language=page.at('meta[name="language"]')['content'].encode('UTF-8')
          rescue
            page_language='N/A'
          end
          begin
            page_author=page.at('meta[name="author"]')['content'].encode('UTF-8')
          rescue
            page_author='N/A'
          end
          begin
            page_copyright=page.at('meta[name="copyright"]')['content'].encode('UTF-8')
          rescue
            page_copyright='N/A'
          end

          # Display Output in Terminal as we crawl
          print_status("#{url}")
          puts "   [".light_blue + "-".white + "] ".light_blue + "Crawler Depth: #{depth}".white unless depth.to_i == 0 or depth == 'N/A'
          puts "   [".light_blue + "-".white + "] ".light_blue + "Response Code: #{code}".white unless code.nil? or code == 'N/A'
          puts "   [".light_blue + "-".white + "] ".light_blue + "Response Time: #{time}".white unless time.nil? or time == 'N/A'
          puts "   [".light_blue + "-".white + "] ".light_blue + "Response Size: #{size}".white unless size.nil? or size == 'N/A'
          puts "   [".light_blue + "-".white + "] ".light_blue + "Content-Length: #{content_length}".white unless content_length .nil? or content_length == 'N/A'
          puts "   [".light_blue + "-".white + "] ".light_blue + "Redirects to: #{redirect_to}".white unless redirect_to.nil? or redirect_to == 'N/A'
          puts "   [".light_blue + "-".white + "] ".light_blue + "Meta Info:".white if page_title != 'N/A' or page_keywords != 'N/A' or page_description != 'N/A' or page_language != 'N/A' or page_author != 'N/A'
          puts "      [".light_blue + "+".white + "] ".light_blue + "Title: #{page_title}".white if page_title != 'N/A'
          puts "      [".light_blue + "+".white + "] ".light_blue + "Generator: #{page_generator}".white if page_generator != 'N/A'
          puts "      [".light_blue + "+".white + "] ".light_blue + "Keywords: #{page_keywords}".white if page_keywords != 'N/A'
          puts "      [".light_blue + "+".white + "] ".light_blue + "Descr: #{page_description}".white if page_description != 'N/A'
          puts "      [".light_blue + "+".white + "] ".light_blue + "Lang: #{page_language}".white if page_language != 'N/A'
          puts "      [".light_blue + "+".white + "] ".light_blue + "Author: #{page_author}".white if page_author != 'N/A'

          # phpBB Forum Checks
          if (page.body =~ /src=.+\/logo_phpBB.gif|We request you retain the full copyright notice below including the link to www.phpbb.com./i or (page.body =~ /href=.+www.phpbb.com/i and page.body =~ /powered by/i)) and @phpbb_forum == 'N/A'
            phpbb_forum = 'N/A'
            phpbb = PHPBBChecks.new(page.url.to_s)
            version = phpbb.changelog_checksum_version_finder
            if not version.nil?
              puts "   [".light_blue + "-".white + "] ".light_blue + "phpBB #{version} CMS Identified!".white
              @phpbb_forum = "#{version}"
              phpbb_forum = "#{version}"
            else
              puts "   [".light_blue + "-".white + "] ".light_blue + "phpBB CMS thought to be in use based on page Source".white
            end
            # Run more phpBB Audits and Checks from here.....?
          else
            phpbb_forum = 'N/A'
          end

          if page.url.to_s =~ /\/FCKeditor\/|\/CFWebstore\/|\/editor\/filemanager\/|\/CKeditor\/|\/fck\/editor\/|\/browser\/default\/connectors\//i
            # Run some checks to see if its a vuln version.....if we didnt find it already of course....
            if not $config['FCKEDITOR']['FOUND']
              fck = FCKEditor.new(page.url.to_s)
              fck_v = fck.version_check # Test for Known FCKeditor Version Disclosures
              if fck_v.nil?
                fckeditor = 'Possible'
                puts "   [".light_blue + "-".white + "] ".light_blue + "FCKeditor may be in use".white
              else
                fckeditor = 'Possible'
                puts "   [".light_green + "+".white + "] ".light_green + "FCKeditor is in use!".white
                puts "      [".light_green + "-".white + "] ".light_green + "FCKeditor Version: #{fck_v}".white
                fck.uploader_file_check   # Test for known locations of FCKEditor Uploader Files
                $config['FCKEDITOR']['FOUND']=true
              end
            end
          else
            fckeditor = 'N/A'
          end

          # Check Response Page for Verbose Error Messages
          # If present may indicate a possible vulnerability
          # Any findings are logged to output/host/vuln for follow up
          if quick_regex_check(page.url.to_s, page.body)
            vulnerable='Vulnerable'
            # more code to do something based on vulnerability, idk...?
          else
            vulnerable='N/A'
          end

          # Key Headers Extraction
          if not page.headers['server'].nil? and page.headers['server'].size > 0
            key_headerz.store('Server', page.headers['server'][0]) unless key_headerz.include?(page.headers['server'][0])
            @key_headerz.store('Server', page.headers['server'][0]) unless @key_headerz.include?(page.headers['server'][0])
            puts "   [".light_blue + "-".white + "] ".light_blue + "Server: #{page.headers['server'][0]}".white
          end
          if not page.headers['powered-by'].nil? and page.headers['powered-by'].size > 0
            key_headerz.store('Powered-By', page.headers['powered-by'][0]) unless key_headerz.include?(page.headers['powered-by'][0])
            @key_headerz.store('Powered-By', page.headers['powered-by'][0]) unless @key_headerz.include?(page.headers['powered-by'][0])
            puts "   [".light_blue + "-".white + "] ".light_blue + "Powered-By: #{page.headers['powered-by'][0]}".white
          end
          if not page.headers['x-powered-by'].nil? and page.headers['x-powered-by'].size > 0
            key_headerz.store('X-Powered-By', page.headers['x-powered-by'][0]) unless key_headerz.include?(page.headers['x-powered-by'][0])
            @key_headerz.store('X-Powered-By', page.headers['x-powered-by'][0]) unless @key_headerz.include?(page.headers['x-powered-by'][0])
            puts "   [".light_blue + "-".white + "] ".light_blue + "X-Powered-By: #{page.headers['x-powered-by'][0]}".white
          end
          if not page.headers['x-aspnet-version'].nil? and page.headers['x-aspnet-version'].size > 0
            key_headerz.store('X-AspNet-Version', page.headers['x-aspnet-version'][0]) unless key_headerz.include?(page.headers['x-aspnet-version'][0])
            @key_headerz.store('X-AspNet-Version', page.headers['x-aspnet-version'][0]) unless @key_headerz.include?(page.headers['x-aspnet-version'][0])
            puts "   [".light_blue + "-".white + "] ".light_blue + "X-AspNet-Version: #{page.headers['x-aspnet-version'][0]}".white
          end
          if not page.headers['x-aspnetmvc-version'].nil? and page.headers['x-aspnetmvc-version'].size > 0
            key_headerz.store('X-AspNetMvc-Version', page.headers['x-aspnetmvc-version'][0]) unless key_headerz.include?(page.headers['x-aspnetmvc-version'][0])
            @key_headerz.store('X-AspNetMvc-Version', page.headers['x-aspnetmvc-version'][0]) unless @key_headerz.include?(page.headers['x-aspnetmvc-version'][0])
            puts "   [".light_blue + "-".white + "] ".light_blue + "X-AspNetMvc-Version: #{page.headers['x-aspnetmvc-version'][0]}".white
          end

          # Take note of Cookies being set
          if not page.headers['set-cookie'].nil? and page.headers['set-cookie'].size > 0
            puts "   [".light_blue + "-".white + "] ".light_blue + "Received Cookie(s):".white
            page.headers['set-cookie'].each do |cookie|
              puts "      #{cookie}".white
              key = cookie.split('=')[0]
              value = cookie.split('=')[1]
              z.puts "URL: " + page.url.to_s
              z.puts cookie + "\n\n"
              @cookiez << cookie if not @cookiez.include?(cookie)
            end
          end

          if not body.nil? and body != 'N/A'
            scripts_count = body.search("//script").count # JS Scripts Count on page
            if scripts_count > 0
              puts "   [".light_blue + "-".white + "] ".light_blue + "#{scripts_count} Script Tags".white
            end
            iframes_count = body.search("//iframes").count # iframe Count on page
            if iframes_count > 0
              puts "   [".light_blue + "-".white + "] ".light_blue + "#{iframes_count} iframes".white
            end
          else
            scripts_count = 0
            iframes_count = 0
          end

          # Form Finder, remember not everyone uses proper syntax or naming...
          # Start wider and slim down as we can...
          if page.body =~ /<form.+name=([\\'"].+[\\'"]).+?>|<form.+method=([\\'"].+[\\'"]).+?>|<form.+action=([\\'"].+[\\'"]).+?>/i
            form_names=[]
            action_formz = page.body.match(/<form.+action=([\\'"].+[\\'"]).+?>/i)
            method_formz = page.body.match(/<form.+method=([\\'"].+[\\'"]).+?>/i)
            name_formz = page.body.match(/<form.+name=([\\'"].+[\\'"]).+?>/i)
            formz = action_formz.to_a + method_formz.to_a + name_formz.to_a
            formz = formz.uniq!
            form_count = formz.size unless formz.nil?
            form_count = 0 if formz.nil?
            if not formz.nil? and formz.size > 0
              mz=[]; az=[];
              form_count = formz.size
              puts "   [".light_blue + "-".white + "] ".light_blue + "#{form_count} Forms".white
              formz.to_a.each do |m|
                f_str = m.sub('<form ', '').sub(/^[\\'"]/, '')
                if f_str =~ /name=[\\'"](.+)[\\'"]?/i
                  form_name = $1.chomp.split(' ')[0].sub(/[\\'"]$/, '')
                end
                form_names << form_name unless form_names.include?(form_name) or form_name.nil?
                if f_str =~ /method=[\\'"](.+)[\\'"]?/i
                  method = $1.chomp.split(' ')[0].sub(/>$/, '').sub(/[\\'"]$/, '')
                end
                if f_str =~ /action=[\\'"](.+)[\\'"]?/i
                  action = $1.chomp.split(' ')[0].sub(/[\\'"]$/, '')
                  if not action =~ /^http/i
                    action = page.to_absolute(action) # Convert relative links to absolute links
                  end
                end
                # Try to get form input parameters when we can get a clean match
                post_params=[]
                if page.body =~ /<form.+name=[\\'"]#{form_name}[\\'"].*?>(.+)<\/form>/im
                  foo=$1
                  bar = foo.match(/name=([\\'"].+[\\'"]).*/im)
                  foo.split(' ').each do |att|
                    if att =~ /name=(.+)/
                      name=att.split('=')[1].to_s.gsub("'", '').gsub('"', '')
                      post_params << name
                    end
                  end
                end
                ff.puts "URL: " + page.url.to_s
                ff.puts "Form Name: #{form_name}" unless form_name.nil?
                ff.puts "Action: #{action}" unless action.nil?
                ff.puts "Method: #{method.upcase}" unless method.nil?
                ff.puts "Parameter(s): #{post_params.join(', ')}" if post_params.size > 0
                ff.puts "\n\n"
                if form_name.nil?
                  pad = '      '
                else
                  pad = '        '
                end
                puts "      [".light_blue + "+".white + "] ".light_blue + "Form Name: #{form_name}".white unless form_name.nil?
                puts "#{pad}[".light_blue + "-".white + "] ".light_blue + "Action: #{action}".white unless action.nil? or (az.include?(action) and form_name.nil?)
                puts "#{pad}[".light_blue + "-".white + "] ".light_blue + "Method: #{method.upcase}".white unless method.nil? or (mz.include?(method) and form_name.nil?)
                puts "           [".light_blue + "-".white + "] ".light_blue + "Parameter(s): #{post_params.join(', ')}".white if post_params.size > 0
                az << action unless action.nil? or az.include?(action)
                mz << method unless method.nil? or mz.include?(method)
              end
            end
          else
            form_count = 0
          end

          # Log url links to file as we crawl
          f.puts url

          # Check for emails in page body while we are here
          emails=[]
          emails_regex.match(page.body) do |email|
            if not @emails.include?(email.to_s.strip.chomp) and email.to_s.strip.chomp =~ /^([a-zA-Z0-9_\-\.]+)@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.)|(([a-zA-Z0-9\-]+\.)+))([a-zA-Z]{2,4}|[0-9]{1,3})(\]?)$/ # Stricter regex to validate bfore adding to our list
              @emails << email.to_s.strip.chomp
            end
            emails << email.to_s.strip.chomp and email.to_s.strip.chomp =~ /^([a-zA-Z0-9_\-\.]+)@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.)|(([a-zA-Z0-9\-]+\.)+))([a-zA-Z]{2,4}|[0-9]{1,3})(\]?)$/
          end
          if emails.empty?
            emails = 'N/A'
          end

          # Keep a copy of the page content in case we want to do something with body content later
          # Parse content, do comparisons against previous crawler sessions (differ user-agent testing or something)
          # Idk, just know it will be usefull sometime later...
          if not page.body.nil? and not page.body == ''
            body_store=page.body
          else
            body_store='N/A'
          end
          # If requested. log additional info to MongoDB for post analysis
          if $config['CRAWLER']['MONGO_SUPPORT']
            the_goods = { 'url' => url, 'body' => body_store, 'depth' => depth, 'code' => code, 'time' => time, 'size' => size, 'content-length' => content_length, 'redirect_to' => redirect_to, 'key_headers' => key_headerz, 'cookies' => page.headers['set-cookie'], 'title' => page_title, 'description' => page_description, 'keywords' => page_keywords, 'generator' => page_generator, 'language' => page_language, 'author' => page_author, 'copyright' => page_copyright, 'forms' => form_count, 'scripts' => scripts_count, 'iframes' => iframes_count, 'fckeditor' => fckeditor, 'phpbb' => phpbb_forum, 'vulnerable' => vulnerable, 'emails' => emails }

            @mongodb_collection.insert the_goods
          end
        end # End on_every_page block
      end # End Anemone crawler
      f.close
      ff.close
      z.close
      break
    end # End while(true) loop

    link_count = File.open(@outfile).readlines.sort.uniq.size

    if link_count.to_i > 0
      cls
      banner
      print_good("Site Crawler has Completed Scan!")
      crawl_parser
    else
      puts
      print_good("Crawler Session Complete!")
      print_caution("...")
      print_error("No Links Were Found, sorry...")
      print_error("Check base path and try again or check things manually to confirm....")
      puts
    end
  end

  # Parse crawler results file
  # Sorts findings into categorized files
  def crawl_parser(file=@outfile)
    mcount=0  # Multi Parameter Links Count
    scount=0  # Single Parameter Links Count
    nocount=0 # No Parameter Links Count

    print_status("Running Parser on #{file}....")
    links = File.open(file).readlines.sort.uniq
    link_count = File.open(file).readlines.sort.uniq.size

    # placeholder arrays
    spreadsheetz=[]; executablez=[]; no_params=[]; test_keys=[]; noparamz=[]; archivez=[]; testlink=[]; 
    opendocz=[]; outlookz=[]; paramz=[]; imagez=[]; audioz=[]; videoz=[]; flashz=[]; multi=[]; vcardz=[];
    bkupz=[]; jsz=[]; confz=[]; wordz=[]; xmlz=[]; pazz=[]; pdfz=[]; txtz=[]; pptz=[]; dbz=[]; axd=[];
    asp_files=[]; cfm_files=[]; html_files=[]; jsp_files=[]; php_files=[];

    links.each do |link|
      if /\/.+\.asp$|\/.+\.asp?.+|\/.+\.asp\/.+|\/.+\.aspx$|\/.+\.aspx?.+|\/.+\.aspx\/.+/i.match(link)
        asp_files << link.chomp if not asp_files.include?(link.chomp)
      end
      if /\/.+\.cfm$|\/.+\.cfm?.+|\/.+\.cfm\/.+/i.match(link)
        cfm_files << link.chomp if not cfm_files.include?(link.chomp)
      end
      if /\/.+\.html$|\/.+\.html?.+|\/.+\.html\/.+/i.match(link)
        html_files << link.chomp if not html_files.include?(link.chomp)
      end
      if /\/.+\.jsp$|\/.+\.jsp?.+|\/.+\.jsp\/.+/i.match(link)
        jsp_files << link.chomp if not jsp_files.include?(link.chomp)
      end
      if /\/.+\.php$|\/.+\.php?.+|\/.+\.php\/.+/i.match(link)
        php_files << link.chomp if not php_files.include?(link.chomp)
      end
      begin
        # parse out parameters if they are present
        # if no parameters it will error raise NoMethodError to be handled by rescue statement
        param = URI.parse(link).query

        # break paramaters into hash [ "parameter" => "value" ] formatting held in storage for easier manipulation
        paramsHash = Hash[URI.parse(link).query.split('&').map{ |q| q.split('=') }] 

        # Parse according to the number of parameters in link		
        ###### Handle Single Parameter links ######
        if paramsHash.length == 1
          scount += 1
          paramz << link
          paramsHash.each do |key, value|
            if value =~ /^\d+$/ # if value is integer replace and then we unique ;)
              testlink << link.sub(/#{value}/, '1') 
            else
              testlink << link # keep strings since they can be funky sometimes & easier to unique
            end
            if not test_keys.include?(key)
              test_keys << key
            end
          end
        elsif paramsHash.length > 1
          ###### Handle Multi Parameter links ######
          mcount += 1
          paramz << link
          paramsHash.keys.each do |key|
            if not test_keys.include?(key)
              test_keys << key
              multi << link.chomp
            end
          end
        end
      ###### Handle NO Parameter links ######
      rescue NoMethodError
        if nocount < 10 # We only need a sample
          no_params << link
          nocount += 1
        end
        # Parse over links we're ditching & sort into appropriate results files (in case that info is needed for follow up l8r)
        if /\/.+\.pdf/i.match(link)
          pdfz << link.chomp
        elsif /\/.+\.doc/i.match(link)
          wordz << link.chomp
        elsif /\/.+\.js|\/.+\.javascript/i.match(link)
          jsz << link.chomp
        elsif /\/.+\.txt|\/.+\.rtf/i.match(link)
          txtz << link.chomp
        elsif /\/.+\.png|\/.+\.jpg|\/.+\.jpeg|\/.+\.gif|\/.+\.bmp|\/.+\.exif|\/.+\.tiff/i.match(link)
          imagez << link.chomp
        elsif /\/.+\.msg/i.match(link)
          outlookz << link.chomp
        elsif /\/.+\.odt/i.match(link)
          opendocz << link.chomp
        elsif /\/.+\.csv|\/.+\.xlr|\/.+\.xls/i.match(link)
          spreadsheetz << link.chomp
        elsif /\/.+\.pps|\/.+\.ppt/i.match(link)
          pptz << link.chomp
        elsif /\/.+\.tar|\/.+\.zip|\/.+\.7z|\/.+\.cbr|\/.+\.deb|\/.+\.gz|\/.+\.bz|\/.+\.pkg|\/.+\.rar|\/.+\.rpm|\/.+\.sit/i.match(link)
          archivez << link.chomp
        elsif /\/.+\.vcf/i.match(link)
          vcardz << link.chomp
        elsif /\/.+\.xml/i.match(link)
          xmlz << link.chomp
        elsif /\/.+\.m3u|\/.+\.m4a|\/.+\.mp3|\/.+\.mpa|\/.+\.wav|\/.+\.wma/i.match(link)
          audioz << link.chomp
        elsif /\/.+\.avi|\/.+\.mov|\/.+\.mp4|\/.+\.mpg|\/.+\.srt|\/.+\.vob|\/.+\.wmv/i.match(link)
          videoz << link.chomp
        elsif /\/.+\.swf|\/.+\.flv/i.match(link)
          flashz << link.chomp
        elsif /\/.+\.sql|\/.+\.accdb|\/.+\.db|\/.+\.mdb|\/.+\.pdb/i.match(link)
          dbz << link.chomp
        elsif /\/.+\.apk|\/.+\.app|\/.+\.bat|\/.+\.cgi|\/.+\.exe|\/.+\.gadget|\/.+\.jar|\/.+\.pif|\/.+\.vbs|\/.+\.wsf/i.match(link)
          executablez << link.chomp
        elsif /\/.+\.bak|\/.+\.tmp|\/.+\.bk/i.match(link)
          bkupz << link.chomp
        elsif /\/.+\.conf/i.match(link)
          confz << link.chomp
        elsif /\/.+\.passwd|\/.+\.htpasswd/i.match(link)
          pazz << link.chomp
        elsif /\/.+\.axd/i.match(link)
          axd << link.chomp
        else
          noparamz << link
        end
      end
    end

    # Sort & Remove Duplicates
    no_params = no_params.sort.uniq unless no_params.empty? or no_params.nil?
    test_keys = test_keys.sort.uniq unless test_keys.empty? or test_keys.nil?
    testlink = testlink.sort.uniq unless testlink.empty? or testlink.nil?
    multi = multi.sort.uniq unless multi.empty? or multi.nil?
    injtestlinks=[]
    print_status("...")
    sleep(2)

    print_good("Crawler Post Parsing Results: ")
    print_status("###############################")
    print_good("Site: #{@site}")
    print_good("Crawled from: #{@url}")
    print_good("User-Agent: #{$config['HTTP']['HTTP_USER_AGENT']}")
    if @limit == 0
      print_good("Link Limit: None")
    else
      print_good("Link Limit: #{@limit}")
    end
    print_good("Thread Count: #{@thread_count}")
    print_status("###############################")
    print_good("All Results Stored In: #{@outdir}")

    if not asp_files.nil? and asp_files.size > 0
      f=File.open("#{@outdir}asp_files.links", 'w+')
      asp_files.sort.uniq.each do |a|
        f.puts a.chomp
      end
      f.close
    end
    if not cfm_files.nil? and cfm_files.size > 0
      f=File.open("#{@outdir}cfm_files.links", 'w+')
      cfm_files.sort.uniq.each do |a|
        f.puts a.chomp
      end
      f.close
    end
    if not html_files.nil? and html_files.size > 0
      f=File.open("#{@outdir}html_files.links", 'w+')
      html_files.sort.uniq.each do |a|
        f.puts a.chomp
      end
      f.close
    end
    if not jsp_files.nil? and jsp_files.size > 0
      f=File.open("#{@outdir}jsp_files.links", 'w+')
      jsp_files.sort.uniq.each do |a|
        f.puts a.chomp
      end
      f.close
    end
    if not php_files.nil? and php_files.size > 0
      f=File.open("#{@outdir}php_files.links", 'w+')
      php_files.sort.uniq.each do |a|
        f.puts a.chomp
      end
      f.close
    end

    if (not @key_headerz.nil? and @key_headerz.size > 0) or (not @cookiez.nil? and @cookiez.size > 0)
      puts
      print_good("Information from Server Responses: ")
    end
    if not @key_headerz.nil? and @key_headerz.size > 0
      @key_headerz.each do |key, value|
        puts "   [".light_green + "-".white + "] ".light_green + "#{key}: #{value}".white
      end
      puts if @cookiez.nil? or @cookiez.size == 0
    end
    # Identify Application/Servers by Known Cookie Names
    # https://www.owasp.org/index.php/Category:OWASP_Cookies_Database
    if not @cookiez.nil? and @cookiez.size > 0
      displayed=[]
      @cookiez.each do |cookie|
        key = cookie.split('=')[0]
        if not displayed.include?(key)
          displayed << key
          case key
          when /^ASPSESSIONID.+|^ASP\.NET_SessionId/
            puts "   [".light_green + "-".white + "] ".light_green + "Microsoft IIS Server Identified via Cookies".white
            puts "      [".light_green + "+".white + "] ".light_green + "#{key}".white
          when 'JSESSIONID'
            puts "   [".light_green + "-".white + "] ".light_green + "J2EE Application Server Identified via Cookies".white
            puts "      [".light_green + "+".white + "] ".light_green + "#{key}".white
          when 'PHPSESSION','PHPSESSID'
            puts "   [".light_green + "-".white + "] ".light_green + "PHP Application Server Identified via Cookies".white
            puts "      [".light_green + "+".white + "] ".light_green + "#{key}".white
          when 'CFID','CFTOKEN','CFGLOBALS'
            puts "   [".light_green + "-".white + "] ".light_green + "Coldfusion Server Identified via Cookies".white
            puts "      [".light_green + "+".white + "] ".light_green + "#{key}".white
          when 'ns_af'
            puts "   [".light_green + "-".white + "] ".light_green + "Citrix Netscalar Firewall Identified via Cookies".white
            puts "      [".light_green + "+".white + "] ".light_green + "#{key}".white
          when /^wiki\d+_session$/
            puts "   [".light_green + "-".white + "] ".light_green + "MediaWiki CMS Identified via Cookies".white
            puts "      [".light_green + "+".white + "] ".light_green + "#{key}".white
          when 'WebLogicSession'
            puts "   [".light_green + "-".white + "] ".light_green + "BEA WebLogic J2EE Application Server Identified via Cookies".white
            puts "      [".light_green + "+".white + "] ".light_green + "#{key}".white
          when /^BiGip/i
            puts "   [".light_green + "-".white + "] ".light_green + "F5 BIG-IP Load Balancer Identified via Cookies".white
            puts "      [".light_green + "+".white + "] ".light_green + "#{key}".white
          when 'SERVERID'
            puts "   [".light_green + "-".white + "] ".light_green + "Possible HAProxy Identified via Cookies".white
            puts "      [".light_green + "+".white + "] ".light_green + "#{key}".white
          when 'SaneID'
            puts "   [".light_green + "-".white + "] ".light_green + "Unica (SANE) NetTracker Identified via Cookies".white
            puts "      [".light_green + "+".white + "] ".light_green + "#{key}".white
          when 'ssuid','vgnvisitor'
            puts "   [".light_green + "-".white + "] ".light_green + "Vignette Content Manager Identified via Cookies".white
            puts "      [".light_green + "+".white + "] ".light_green + "#{key}".white
          when 'SESSION_ID'
            puts "   [".light_green + "-".white + "] ".light_green + "IBM Net.Commerce Server Identified via Cookies".white
            puts "      [".light_green + "+".white + "] ".light_green + "#{key}".white
          when 'NSES40Session'
            puts "   [".light_green + "-".white + "] ".light_green + "Red Hat Netscape Enterprise Application Server Identified via Cookies".white
            puts "      [".light_green + "+".white + "] ".light_green + "#{key}".white
          when 'iPlanetUserId'
            puts "   [".light_green + "-".white + "] ".light_green + "Sun iPlanet Web Server Identified via Cookies".white
            puts "      [".light_green + "+".white + "] ".light_green + "#{key}".white
          when 'gx_session_id_','JROUTE'
            puts "   [".light_green + "-".white + "] ".light_green + "Sun Java System Application Server Identified via Cookies".white
            puts "      [".light_green + "+".white + "] ".light_green + "#{key}".white
          when 'RMID'
            puts "   [".light_green + "-".white + "] ".light_green + "RealMedia OpenAdStream Media Server Identified via Cookies".white
            puts "      [".light_green + "+".white + "] ".light_green + "#{key}".white
          when 'RoxenUserID'
            puts "   [".light_green + "-".white + "] ".light_green + "Roxen Web Server Identified via Cookies".white
            puts "      [".light_green + "+".white + "] ".light_green + "#{key}".white
          when 'JServSessionIdroot'
            puts "   [".light_green + "-".white + "] ".light_green + "Apache JServ Web Server Identified via Cookies".white
            puts "      [".light_green + "+".white + "] ".light_green + "#{key}".white
          when 'sesessionid','Ltpatoken','Ltpatoken2'
            puts "   [".light_green + "-".white + "] ".light_green + "IBM WebSphere Application Server Identified via Cookies".white
            puts "      [".light_green + "+".white + "] ".light_green + "#{key}".white
          when 'LtpatokenExpiry','LtpatokenUsername','DomAuthSessID'
            puts "   [".light_green + "-".white + "] ".light_green + "IBM Lotus Domino Application Server Identified via Cookies".white
            puts "      [".light_green + "+".white + "] ".light_green + "#{key}".white
          when 'PD-S-SESSION-ID', /^PD_STATEFUL_.+-.+-.+-.+-.+/
            puts "   [".light_green + "-".white + "] ".light_green + "IBM Tivoli Access Manager WebSeal Identified via Cookies".white
            puts "      [".light_green + "+".white + "] ".light_green + "#{key}".white
          when 'WEBTRENDS_ID'
            puts "   [".light_green + "-".white + "] ".light_green + "WebTrends Tracking Server Identified via Cookies".white
            puts "      [".light_green + "+".white + "] ".light_green + "#{key}".white
          when 'SS_X_CSINTERSESSIONID','CSINTERSESSIONID'
            puts "   [".light_green + "-".white + "] ".light_green + "OpenMarket/FatWire Content Server Identified via Cookies".white
            puts "      [".light_green + "+".white + "] ".light_green + "#{key}".white
          when '_sn'
            puts "   [".light_green + "-".white + "] ".light_green + "Siebel CRM Identified via Cookies".white
            puts "      [".light_green + "+".white + "] ".light_green + "#{key}".white
          when /^BCSI-CSC.......$/
            puts "   [".light_green + "-".white + "] ".light_green + "Bluecoat Proxy Server Identified via Cookies".white
            puts "      [".light_green + "+".white + "] ".light_green + "#{key}".white
          when /phpbb/
            if key =~ /phpbb([\d])mysql_data/
              puts "   [".light_green + "-".white + "] ".light_green + "phpBB v2 Identified via Cookies".white
            else
              puts "   [".light_green + "-".white + "] ".light_green + "phpBB v3 Identified via Cookies".white
            end
            puts "      [".light_green + "+".white + "] ".light_green + "#{key}".white
          end
        end
      end
      puts
    end

    print_good("Links Found: #{link_count}")
    if not @cookies.nil? and @cookies.size > 0
      puts "   [".light_green + "-".white + "] ".light_green + "#{@cookies.sort.uniq.size} Cookies Received while crawling".white
      puts "      [".light_green + "+".white + "] ".light_green + "Cooke details stored in #{@outdir}cookies.txt".white
    end

    if not @meta_keywords.nil? and @meta_keywords.size > 0
      f=File.open("#{@outdir}keywords.txt", 'w+')
      f.puts @meta_keywords.sort.uniq.join(",")
      f.close
      puts "   [".light_green + "-".white + "] ".light_green + "#{@meta_keywords.sort.uniq.size} Keywords".white
    end

    # Emails
    if not @emails.empty?
      @emails.uniq!
      f=File.open("#{@outdir}temp.emails", 'w+')
      @emails.each do |email|
        f.puts email
      end
      f.close

      # Because Ruby built-in uniq function doesn't seem to be fully doing the job we use some OS magic to make sure it is unique emails only....
      commandz("cat #{@outdir}temp.emails | sort -u > #{@outdir}emails.txt")
      count = File.open("#{@outdir}emails.txt").readlines.size
      File.delete("#{@outdir}temp.emails") if File.exists?("#{@outdir}temp.emails")
      puts "   [".light_green + "-".white + "] ".light_green + "#{count} Possible Emails".white
    end

    # NO Parameter Links
    if not noparamz.empty?
      zfile="no_paramater"
      f = File.new("#{@outdir}#{zfile}.links", "a+")
      noparamz.each do |line|
        f.puts line.chomp
      end
      f.close
      puts "   [".light_green + "-".white + "] ".light_green + "#{noparamz.length} No Paramater Links".white
    end

    # Parameter Links
    if not paramz.empty?
      zfile="paramater"
      f = File.new("#{@outdir}#{zfile}.links", "a+")
      paramz.each do |line|
        f.puts line.chomp
      end
      f.close
      puts "   [".light_green + "-".white + "] ".light_green + "#{paramz.length} Links with Testable Paramaters".white
    end

    # Javascript Files
    if not jsz.empty?
      zfile="js"
      f = File.new("#{@outdir}#{zfile}.links", "a+")
      jsz.each do |line|
        f.puts line.chomp
      end
      f.close
      puts "   [".light_green + "-".white + "] ".light_green + "#{jsz.length} JS File Links".white
    end

    # PDF Files
    if not pdfz.empty?
      zfile="pdf"
      f = File.new("#{@outdir}#{zfile}.links", "a+")
      pdfz.each do |line|
        f.puts "#{line.chomp}"
      end
      f.close
      puts "   [".light_green + "-".white + "] ".light_green + "#{pdfz.length} PDF Links".white
    end

    # Word Docs
    if not wordz.empty?
      zfile="word_docs"
      f = File.new("#{@outdir}#{zfile}.links", "a+")
      wordz.each do |line|
        f.puts line.chomp
      end
      f.close
      puts "   [".light_green + "-".white + "] ".light_green + "#{wordz.length} MS Word File Links".white
    end

    # Text Files
    if not txtz.empty?
      zfile="text"
      f = File.new("#{@outdir}#{zfile}.links", "a+")
      txtz.each do |line|
        f.puts line.chomp
      end
      f.close
      puts "   [".light_green + "-".white + "] ".light_green + "#{txtz.length} Text Files Links".white
    end

    # Outlook Message Files
    if not outlookz.empty?
      zfile="outlook"
      f = File.new("#{@outdir}#{zfile}.links", "a+")
      outlookz.each do |line|
        f.puts line.chomp
      end
      f.close
      puts "   [".light_green + "-".white + "] ".light_green + "#{outlookz.length} Outlook Message File Links".white
    end

    # OpenDoc Documents
    if not opendocz.empty?
      zfile="open_doc"
      f = File.new("#{@outdir}#{zfile}.links", "a+")
      opendocz.each do |line|
        f.puts line.chomp
      end
      f.close
      puts "   [".light_green + "-".white + "] ".light_green + "#{opendocz.length} OpenDoc File Links".white
    end

    # Spreadsheet Files
    if not spreadsheetz.empty?
      zfile="spreadsheet"
      f = File.new("#{@outdir}#{zfile}.links", "a+")
      spreadsheetz.each do |line|
        f.puts line.chomp
      end
      f.close
      puts "   [".light_green + "-".white + "] ".light_green + "#{spreadsheetz.length} SpreadSheet File Links".white
    end

    # PowerPoint Slide Decks
    if not pptz.empty?
      zfile="powerpoint"
      f = File.new("#{@outdir}#{zfile}.links", "a+")
      pptz.each do |line|
        f.puts line.chomp
      end
      f.close
      puts "   [".light_green + "-".white + "] ".light_green + "#{pptz.length} PowerPoint Files Links".white
    end

    # Archive Files
    if not archivez.empty?
      zfile="archives"
      f = File.new("#{@outdir}#{zfile}.links", "a+")
      archivez.each do |line|
        f.puts line.chomp
      end
      f.close
      puts "   [".light_green + "-".white + "] ".light_green + "#{archivez.length} Archive File Links".white
    end

    # Vcard Contact File
    if not vcardz.empty?
      zfile="vCard"
      f = File.new("#{@outdir}#{zfile}.links", "a+")
      vcardz.each do |line|
        f.puts line.chomp
      end
      f.close
      puts "   [".light_green + "-".white + "] ".light_green + "#{vcardz.length} vCard File Links".white
    end

    # XML Files
    if not xmlz.empty?
      zfile="XML"
      f = File.new("#{@outdir}#{zfile}.links", "a+")
      xmlz.each do |line|
        f.puts line.chomp
      end
      f.close
      puts "   [".light_green + "-".white + "] ".light_green + "#{xmlz.length} XML File Links".white
    end

    # Audio Files
    if not audioz.empty?
      zfile="audio"
      f = File.new("#{@outdir}#{zfile}.links", "a+")
      audioz.each do |line|
        f.puts line.chomp
      end
      f.close
      puts "   [".light_green + "-".white + "] ".light_green + "#{audioz.length} Audio File Links".white
    end

    # Video Files
    if not videoz.empty?
      zfile="video"
      f = File.new("#{@outdir}#{zfile}.links", "a+")
      videoz.each do |line|
        f.puts line.chomp
      end
      f.close
      puts "   [".light_green + "-".white + "] ".light_green + "#{videoz.length} Video File Links".white
    end

    # Flash Files
    if not flashz.empty?
      zfile="flash"
      f = File.new("#{@outdir}#{zfile}.links", "a+")
      flashz.each do |line|
        f.puts line.chomp
      end
      f.close
      puts "   [".light_green + "-".white + "] ".light_green + "#{flashz.length} Flash File Links".white
    end

    # Database Files
    if not dbz.empty?
      zfile="database"
      f = File.new("#{@outdir}#{zfile}.links", "a+")
      dbz.each do |line|
        f.puts line.chomp
      end
      f.close
      puts "   [".light_green + "-".white + "] ".light_green + "#{dbz.length} Database File Links".white
    end
	
    # Executables
    if not executablez.empty?
      zfile="executable"
      f = File.new("#{@outdir}#{zfile}.links", "a+")
      executablez.each do |line|
        f.puts line.chomp
      end
      f.close
      puts "   [".light_green + "-".white + "] ".light_green + "#{executablez.length} Executable File Links".white
    end

    # Backup Files
    if not bkupz.empty?
      zfile="backup"
      f = File.new("#{@outdir}#{zfile}.links", "a+")
      bkupz.each do |line|
        f.puts line.chomp
      end
      f.close
      puts "   [".light_green + "-".white + "] ".light_green + "#{bkupz.length} Links to BackUp Files".white
    end

    # Config Files
    if not confz.empty?
      zfile="configuration"
      f = File.new("#{@outdir}#{zfile}.links", "a+")
      confz.each do |line|
        f.puts line.chomp
      end
      f.close
      puts "   [".light_green + "-".white + "] ".light_green + "#{confz.length} Config File Links".white
    end

    # Password Files
    if not pazz.empty?
      zfile="passwords"
      f = File.new("#{@outdir}#{zfile}.links", "a+")
      pazz.each do |line|
        f.puts line.chomp
      end
      f.close
      puts "   [".light_green + "-".white + "] ".light_green + "#{pazz.length} Password File Links".white
    end

    # Image Files
    if not imagez.empty?
      zfile="image"
      f = File.new("#{@outdir}#{zfile}.links", "a+")
      imagez.each do |line|
        f.puts line.chomp
      end
      f.close
      puts "   [".light_green + "-".white + "] ".light_green + "#{imagez.length} Image File Links".white
    end

    # AXD Web Service Calls
    if not axd.empty?
      zfile="axd"
      f = File.new("#{@outdir}#{zfile}.links", "a+")
      axd.each do |line|
        f.puts line.chomp
      end
      f.close
      puts "   [".light_green + "-".white + "] ".light_green + "#{axd.length} AXD Service File Links".white
    end

    print_line("")
    print_good("Other Info.....")
    if not test_keys.empty?
      puts "   [".light_green + "-".white + "] ".light_green + "Found #{test_keys.length} Testable Parameters:".white
      puts "      [".light_green + "+".white + "] ".light_green + "#{test_keys.join(', ').to_s}".white
      print_line("")
    end
    if not testlink.empty?
      puts "   [".light_green + "-".white + "] ".light_green + "Found #{testlink.length} Unique Single Parameter Links (out of #{scount} total): ".white
      testlink.each do |line|
        puts "      [".light_green + "+".white + "] ".light_green + "#{line.chomp}".white
        injtestlinks << line
      end
      print_line("")
    end
    if not multi.empty?
      puts "   [".light_green + "-".white + "] ".light_green + "Found #{multi.length} Unique Multi Parameter Links (out of #{mcount} total): ".white
      multi.each do |line|
        puts "      [".light_green + "+".white + "] ".light_green + "#{line.chomp}".white
        injtestlinks << line
      end
      print_line("")
    end
    if not no_params.empty?
      if no_params.length < 9
        puts "   [".light_green + "-".white + "] ".light_green + "Found the following NO Parameter links: ".white
        nopam = no_params
      else
        puts "   [".light_green + "-".white + "] ".light_green + "10 Randomly Selected No Parameter Links (Out of #{nocount} in Total): ".white
        nopam = no_params.sort_by{rand}[0..9]
      end
      nopam.each do |line|
        puts "      [".light_green + "+".white + "] ".light_green + "#{line.chomp}".white
        injtestlinks << line
      end
      print_line("")
    end
    if not injtestlinks.empty?
      f = File.new("#{@outdir}testable.links", "w+")
      injtestlinks.each do |link|
        f.puts link
      end
      f.close
    end
    print_status("Crawler Session has Finished!")
  end

  # Robots.txt Checker
  # Parse results if present & display
  def robots(log=true)
    target = @url.sub(/\/$/, '') + "/robots.txt"

    if log
      # Setup Logging of positive results
      logdir = RESULTS + 'recon/' + @url.sub('http://', '').sub('https://', '').sub('www.', '').sub(/\/$/, '').split("/")[0]
      logfile = logdir + "/robots.txt"
      disallow_file = logdir + "/robots.disallowed"
      Dir.mkdir(logdir) unless File.exists?(logdir) and File.directory?(logdir)
    end

    c=EasyCurb.new
    res = c.get(target)
    # res => response array => [ response_body, response_code, repsonse_time, response_headers ]
    if res[1] == 200
      f=File.open(logfile, 'w+') if log
      d=File.open(disallow_file, 'w+') if log
      if res[0] =~ /User-agent: .+/i and res[0] =~ /Disallow: .+/i
        f.puts "Found Robots File: #{target}" if log
        print_good("Found Robots File: #{target}")
        print_status("Parsing Robots file......")
        dis=[]
        res[0].split("\n").each do |line|
          f.puts line if log
          if line =~ /User-agent: .+/i
            foo=line.split(' ')
            bar = foo.slice(1, foo.length)
            puts "#{foo[0]}".light_yellow + " #{bar.join(' ')}".white
          elsif line =~ /admin|moderator|cp|control panel|cpanel/i
            foo=line.split(' ')
            bar = foo.slice(1, foo.length)
            puts "#{foo[0]}".light_red + " #{bar.join(' ')}".light_green
          elsif line =~ /user|password|login|editor|manage/i
            foo=line.split(' ')
            bar = foo.slice(1, foo.length)
            puts "#{foo[0]}".light_red + " #{bar.join(' ')}".green
          elsif line =~ /upload|cgi|\/~\w+\//i
            foo=line.split(' ')
            bar = foo.slice(1, foo.length)
            puts "#{foo[0]}".light_red + " #{bar.join(' ')}".light_yellow
          elsif line =~ /sitemap: .+/i
            foo=line.split(' ')
            bar = foo.slice(1, foo.length)
            puts "#{foo[0]}".light_green + " #{bar.join(' ')}".white
          else
            if line =~ /Disallow: .+/i
              foo=line.split(' ')
              bar = foo.slice(1, foo.length)
              puts "#{foo[0]}".light_red + " #{bar.join(' ')}".white
              dis << bar.join(' ') unless dis.include?(bar.join(' '))
            elsif line =~ /Allow: .+/i
              foo=line.split(' ')
              bar = foo.slice(1, foo.length)
              puts "#{foo[0]}".cyan + " #{bar.join(' ')}".white
            else
              print_line("#{line}")
            end
          end
        end
        if not dis.nil? and dis.size > 0
          dis.uniq.sort.each {|x| d.puts x }
        end
        f.close if log
        d.close if log
      else
        print_line("")
        print_error("Robots File Not Found or Format is way off!")
        print_line("")
      end
    elsif res[1] == 301 or res[1] == 302
      puts "[".light_yellow + " REDIRECT ".white + "] ".light_yellow + "#{target}".white
    elsif res[1] == 403
      puts "[".light_red + " Forbidden ".white + "] ".light_red + "#{target}".white
    else
      print_line("")
      print_error("No Robots File Found!")
      print_line("")
    end
    if log and File.exists?(logfile)
      count = File.open(logfile).readlines.size
      if not count.to_i > 0
        # Remove these files if nothing was found
        File.delete(logfile)
        File.delete(disallow_file)
      end
    end
  end

  # Fairly Typical Admin Page Finder, checks against pre-built array list
  # Checks for common form names in source code to try and confirm finds
  # Links are ranked based on form counts and confirmed matches
  def admin(type='php', verbose=true)
    trap("SIGINT") {
      print_error("CTRL+C! Returning to Previous Menu....")
      return
    }
    common_admin = [ "@dmin/", "_admin/", "_adm/", "admin/", "adm/", "admincp/", "admcp/", "cp/", "modcp/", "moderatorcp/", "adminare/", "admins/", "cpanel/", "controlpanel/", "0admin/", "0manager/", "admin1/", "admin2/", "ADMIN/", "administrator/", "ADMON/", "AdminTools/", "administrador/", "administracao/", "painel/", "administracao.XXXX", "administrateur/", "administrateur.XXXX", "beheerder/", "administracion/", "administracion.XXXX", "beheerder.XXXX", "amministratore/", "amministratore.XXXX", "v2/painel/", "db/", "dba/", "dbadmin/", "Database_Administration/", "ADMIN/login.XXXX", "ADMIN/login.XXXX", "Indy_admin/", "LiveUser_Admin/", "Lotus_Domino_Admin/", "PSUser/", "Server.XXXX", "Server/", "ServerAdministrator/", "Super-Admin/", "SysAdmin/", "SysAdmin2/", "UserLogin/", "WebAdmin/", "aadmin/", "acceso.XXXX", "acceso.XXXX", "access.XXXX", "access/", "account.XXXX", "accounts.XXXX", "accounts/", "acct_login/", "adm.XXXX", "adm/admloginuser.XXXX", "adm/index.XXXX", "adm_auth.XXXX", "admin-login.XXXX", "admin.XXXX", "admin/account.XXXX", "admin/admin-login.XXXX", "admin/admin.XXXX", "admin/adminLogin.XXXX", "admin/admin_login.XXXX", "admin/controlpanel.XXXX", "admin/cp.XXXX", "admin/home.XXXX", "admin/index.XXXX", "admin/Login.XXXX", "admin/login.XXXX", "admin1.XXXX", "admin1/", "admin2.XXXX", "admin2/index.XXXX", "admin2/login.XXXX", "admin4_account/", "admin4_colon/", "adminLogin.XXXX", "adminLogin/", "admin_area.XXXX", "admin_area/", "admin_area/admin.XXXX", "admin_area/index.XXXX", "admin_area/login.XXXX", "admin_login.XXXX", "admin-login/", "admin-login/login.XXXX", "admin-login/index.XXXX", "adminarea/", "adminarea/admin.XXXX", "adminarea/index.XXXX", "adminarea/login.XXXX", "admincontrol.XXXX", "admincontrol/", "admincontrol/login.XXXX", "admincp/", "admincp/index.XXXX", "administer/", "administr8.XXXX", "administr8/", "administrador/", "administratie/", "administration.XXXX", "administration/", "administrator.XXXX", "administrator/", "administrator/account.XXXX", "administrator/index.XXXX", "administratoraccounts/", "administratorlogin.XXXX", "administratorlogin/", "administrators.XXXX", "administrators/", "administrivia/", "adminitem.XXXX", "adminitem/", "adminitems.XXXX", "adminitems/", "adminpanel.XXXX", "adminpanel/", "adminpro/", "admins.XXXX", "admins/", "adminsite/", "admloginuser.XXXX", "admon/", "affiliate.XXXX", "auth.XXXX", "authadmin.XXXX", "authenticate.XXXX", "authentication.XXXX", "authuser.XXXX", "autologin.XXXX", "autologin/", "backoffice/admin.XXXX", "banneradmin/", "bb-admin/", "bb-admin/admin.XXXX", "bb-admin/index.XXXX", "bb-admin/login.XXXX", "bbadmin/", "bigadmin/", "blogindex/", "cPanel/", "cadmins/", "ccms/", "ccms/index.XXXX", "cms/", "cms/admin.XXXX", "cms/index.XXXX", "ccp14admin/", "cgi-bin/login.XXXX", "cgi-bin/admin.XXXX", "cgi-bin/admin/index.XXXX", "cgi-bin/admin/admin.XXXX", "cgi-bin/admin/login.XXXX", "cgi/index.XXXX", "cgi/admin.XXXX", "cgi/login.XXXX", "cgi/admin/index.XXXX", "cgi/admin/admin.XXXX", "cgi/admin/login.XXXX", "check.XXXX", "checkadmin.XXXX", "CFIDE/administrator/", "CFIDE/admin/", "CFIDE/", "checklogin.XXXX", "checkuser.XXXX", "cmsadmin.XXXX", "cmsadmin/", "configuration/", "configure/", "control.XXXX", "control/", "controlpanel.XXXX", "controlpanel/", "cp.XXXX", "cp/", "cpanel/", "cpanel_file/", "customer_login/", "cvsadmin/", "database_administration/", "dir-login/", "directadmin/", "ezsqliteadmin/", "fileadmin.XXXX", "fileadmin/", "formslogin/", "globes_admin/", "gallery/login.XXXX", "gallery/admin/", "gallery/admin.XXXX", "gallery/users.XXXX",  "gallery_admin/", "home.XXXX", "hpwebjetadmin/", "instadmin/", "irc-macadmin/", "isadmin.XXXX", "kpanel/", "letmein.XXXX", "letmein/", "log-in.XXXX", "log-in/", "log_in.XXXX", "log_in/", "login-redirect/", "login-us/", "login.XXXX", "login/", "login1.XXXX", "login1/", "login_admin.XXXX", "login_admin/", "login_db/", "login_out.XXXX", "login_out/", "login_user.XXXX", "loginerror/", "loginflat/", "loginok/", "loginsave/", "loginsuper.XXXX", "loginsuper/", "logo_sysadmin/", "logout.XXXX", "logout/", "macadmin/", "maintenance/", "manage.XXXX", "manage/", "management.XXXX", "management/", "manager.XXXX", "manager/", "manuallogin/", "member.XXXX", "member/", "memberadmin.XXXX", "memberadmin/", "members.XXXX", "members/", "member/login.XXXX", "members/login.XXXX", "memlogin/", "meta_login/", "modelsearch/admin.XXXX", "modelsearch/index.XXXX", "modelsearch/login.XXXX", "moderator.XXXX", "moderator/", "moderator/admin.XXXX", "moderator/login.XXXX", "modules/admin/", "myadmin/", "navSiteAdmin/", "newsadmin/", "nsw/admin/login.XXXX", "openvpnadmin/", "pages/admin/", "pages/admin/admin-login.XXXX", "panel-administracion/", "panel-administracion/admin.XXXX", "panel-administracion/index.XXXX", "panel-administracion/login.XXXX", "panel.XXXX", "panel/", "panelc/", "paneldecontrol/", "pgadmin/", "phpSQLiteAdmin/", "phpldapadmin/", "phpmyadmin/", "phpMyAdmin/", "phppgadmin/", "platz_login/", "power_user/", "processlogin.XXXX", "project-admins/", "pureadmin/", "radmind-1/", "radmind/", "rcLogin/", "rcjakar/admin/login.XXXX", "relogin.XXXX", "CFIDE/componentutils/", "root/", "secret/", "secrets/", "secure/", "secure/admin/", "secure/admin/login.XXXX", "security/", "server/", "server_admin_small/", "showlogin/", "sign-in.XXXX", "sign-in/", "sign_in.XXXX", "sign_in/", "signin.XXXX", "signin/", "simpleLogin/", "siteadmin.XXXX", "siteadmin/", "CFIDE/adminapi/base.cfc?wsdl", "siteadmin/index.XXXX", "siteadmin/login.XXXX", "smblogin/", "sql-admin/", "ss_vms_admin_sm/", "sshadmin/", "staradmin/", "sub-login/", "super.XXXX", "super1.XXXX", "super1/", "super_index.XXXX", "super_login.XXXX", "superman.XXXX", "shopping-cart-admin-login.XXXX", "shop/manager/", "shop/admin/", "shop/login.XXXX", "shop/admin/login.XXXX", "store/admin/", "store/login.XXXX", "store/admin/login.XXXX", "store/manager/", "superman/", "supermanager.XXXX", "superuser.XXXX", "superuser/", "supervise/", "supervise/Login.XXXX", "supervisor/", "support_login/", "sys-admin/", "sysadm.XXXX", "sysadm/", "sysadmin.XXXX", "sysadmin/", "sysadmins/", "system-administration/", "system_administration/", "typo3/", "ur-admin.XXXX", "ur-admin/", "user.XXXX", "user/", "useradmin/", "user/login.XXXX", "userlogin.XXXX", "users.XXXX", "users/", "users/login.XXXX", "usr/", "utility_login/", "uvpanel/", "vadmind/", "vmailadmin/", "vorod.XXXX", "vorod/", "vorud.XXXX", "vorud/", "webadmin.XXXX", "webadmin/", "webadmin/admin.XXXX", "webadmin/index.XXXX", "webadmin/login.XXXX", "webmaster.XXXX", "webmaster/", "websvn/", "wizmysqladmin/", "blog/wp-admin/", "wp-admin/", "wp-admin/wp-login.XXXX", "wp/wp-login.XXXX", "blog/wp-login.XXXX", "wp-login.XXXX", "wp-login/", "xlogin/", "yonetici.XXXX", "yonetim.XXXX" ]

    alinks=[] #placeholder for A links
    blinks=[] #placeholder for B links
    clinks=[] #placeholder for C links

    # Setup Logging of results
    logdir = RESULTS + 'recon/' + @url.sub('http://', '').sub('https://', '').sub('www.', '').sub(/\/$/, '').split("/")[0]
    logfile = logdir + "/admin_finder.links"
    Dir.mkdir(RESULTS + 'recon/') unless File.exists?(RESULTS + 'recon/') and File.directory?(RESULTS + 'recon/')
    Dir.mkdir(logdir) unless File.exists?(logdir) and File.directory?(logdir)

    f=File.open(logfile, 'w+')
    f.puts "\nAdmin Page Finder Individual Request Results:\n\n"
    common_admin.uniq.shuffle.each do |page2find|
      target = "#{@url.sub(/\/$/, '')}/#{page2find.sub('.XXXX', ".#{type}")}"
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
  
        agent.get(target)
        if agent.page.code.to_i == 200
          if not $config['ADMIN']['CUSTOM_ERROR'].nil?
            err = $config['ADMIN']['CUSTOM_ERROR']
            if agent.page.body =~ /#{err}/
              f.puts "[ #{agent.page.code.to_i} - CUSTOM MATCH ] #{target}"
              puts "[".light_green + " #{agent.page.code.to_i} - CUSTOM MATCH ".light_yellow + "] ".light_green + "#{target}".white if verbose
              next
            end
          end
          forms = agent.page.forms
          if forms.length == 0
            puts "[".light_green + " #{agent.page.code.to_i} - NO FORMS ".light_yellow + "] ".light_green + "#{target}".white if verbose
            f.puts "[ #{agent.page.code.to_i} - NO FORMS ] #{target}"
            clinks << target
          else
            check=0
            # Check for common form names
            agent.page.forms.each do |form|
              form.fields.each do |field|
                if field.name =~ /login|user|uname|pass|email|member|usr|psswd|admin|upload/i
                  check = 1
                end
              end
            end
            if check.to_i == 0
              f.puts "[ #{agent.page.code.to_i} - NO FORM MATCH ] #{target}"
              puts "[".light_yellow + " #{agent.page.code.to_i} - NO FORM MATCH ".white + "] ".light_yellow + "#{target}".white if verbose
              clinks << target
            else
              f.puts "[ #{agent.page.code.to_i} - FORM MATCH ] #{target}"
              puts "[".light_green + " #{agent.page.code.to_i} - FORM MATCH ".white + "] ".light_green + "#{target}".white if verbose
              alinks << target
            end
          end
        else
          f.puts "[ #{agent.page.code.to_i} ] #{target}"
          puts "[".light_red + " #{agent.page.code.to_i} ".white + "] ".light_red + "#{target}".white if verbose
        end
      rescue OpenSSL::SSL::SSLError => e
        if agent.page.code.to_i == 301 or agent.page.code.to_i == 302
          f.puts "[ #{agent.page.code.to_i} ] #{target}"
          puts "[".light_green + " #{agent.page.code.to_i} ".light_red + "] ".light_green + "#{target}".white if verbose
          blinks << target
        else
          f.puts "[ #{agent.page.code.to_i} ] #{target}"
          f.puts "SSL Cert Issues, likely an admin page with self signed certs causing issue!"
          f.puts "=> #{e}"
          puts "[".light_yellow + " #{agent.page.code.to_i} ".light_red + "] ".light_yellow + "#{target}".white if verbose
          puts "SSL Cert Issues, likely an admin page with self signed certs causing issue".yellow + "!".white if verbose
          puts "=> #{e}".light_red if verbose
          blinks << target
        end
      rescue Errno::ETIMEDOUT
        print_error("Connection Timeout....") if verbose
      rescue Net::HTTP::Persistent::Error
        next
      rescue NoMethodError
        print_error("Problems parsing page forms....") if verbose
        f.puts "\tProblems parsing page forms...."
        next
      rescue Zlib::DataError
        print_error("Problems parsing response....") if verbose
        puts "[".light_red + " #{agent.page.code.to_i} ".white + "] ".light_red + "#{target}".white
      rescue Mechanize::ResponseCodeError => e
        if e.to_s.split(' ')[0] == '404'
          f.puts "[ 404 ] #{target}"
          puts "[".light_red + " 404 ".white + "] ".light_red + "#{target}".white if verbose
        elsif e.to_s.split(' ')[0] == '403'
          puts "[".light_yellow + " 403 ".light_yellow + "] ".light_yellow + "#{target}".white if verbose
          f.puts "[ 403 ] #{target}"
          blinks << target
        elsif e.to_s.split(' ')[0] == '401' #Auth Required!
          f.puts "[ 401 ] #{target}"
          puts "[".light_green + " UnAuthorized ".white + "] ".light_green + "#{target}".white if verbose
          blinks << target
        else
          f.puts "=> #{e}"
          puts "#{e}".light_red if verbose
        end
      end
    end
    f.close

    cls
    banner
    puts
    foo=[]
    alinks = alinks.uniq
    blinks = blinks.uniq
    clinks = clinks.uniq
    foo = alinks + blinks + clinks
    data = File.open(logfile).readlines
    f=File.open(logfile, 'w+')
    f.puts '##################################################'
    f.puts "Scan Results: #{@url}"
    f.puts "Links Found: #{foo.length}"
    if not foo.nil? and not foo.empty?
      puts "[".light_green + "*".white + "] Found the following ".light_green + "#{foo.length}".white + " links".light_green + ": ".white
      if not alinks.empty?
        puts "[".light_green + "*".white + "] Primary Links".light_green + ": ".white
        f.puts "Primary Links: #{alinks.length}"
        alinks.each do |admlinks|
          puts "   [".light_green + "-".white + "] ".light_green + admlinks.white
          f.puts admlinks
        end
      end
      if not blinks.empty?
        puts "\n[".light_green + "*".white + "] Secondary Links".light_green + ": ".white
        f.puts "\nSecondary Links: #{blinks.length}"
        blinks.each do |admlinks|
          puts "   [".light_green + "-".white + "] ".light_green + admlinks.white
          f.puts admlinks
        end
      end
      if not clinks.empty?
        puts "\n[".light_green + "*".white + "] Other Links".light_green + ": ".white
        f.puts "\nOther Links: "
        clinks.each do |admlinks|
          puts "   [".light_green + "-".white + "] ".light_green + admlinks.white
          f.puts admlinks
        end
      end
      puts
      print_status("Admin Scanner Completed!")
    else
      f.puts "\n\n\nNo Links Found!\n\n\n"
      print_line("")
      print_error("No pages were found!")
      print_error("Check base link and try again or follow up manually.....")
      print_line("")
    end
    f.puts '##################################################'
    data.each { |line| f.puts line } 
    f.close
    return alinks, blinks, clinks
  end
end
