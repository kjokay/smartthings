import groovy.json.JsonSlurper

metadata {
	definition (name: "rpi", namespace: "customeyes/smartthings", author: "Kevin Johns") {
		capability "Polling"
		capability "Configuration"
		capability "Refresh"
		capability "Temperature Measurement"
        capability "Switch"
        capability "Sensor"
        capability "Motion Sensor"
        capability "Actuator"
        
        attribute "cpuPercentage", "string"
        attribute "memory", "string"
        attribute "diskUsage", "string"
        attribute "currentIP", "string"
        
        command "subscribe"
        command "resubscribe"
        command "unsubscribe"
        command "restart"
        command "setIpAddress"
	}

    preferences {
        input "ip", "string", title:"IP Address", description: "IP address of your raspberry pi", required: true, displayDuringSetup: true
        input "port", "string", title:"Port", description: "port that the web service is running on", required: true, displayDuringSetup: true        
        input "username", "string", title:"Username", description: "web service username", required: true, displayDuringSetup: true
        input "password", "password", title:"Password", description: "web service password", required: true, displayDuringSetup: true
    }
    
    simulator
    {
        status "on": "1"
        status "off": "0"
	}

	tiles(scale: 2){

        multiAttributeTile(name:"rich-control", type: "motion", canChangeIcon: true){
            tileAttribute ("device.motion", key: "PRIMARY_CONTROL") {
                attributeState "active", label:'motion', icon:"st.motion.motion.active", backgroundColor:"#53a7c0"
                attributeState "inactive", label:'no motion', icon:"st.motion.motion.inactive", backgroundColor:"#ffffff"
                attributeState "offline", label:'${name}', icon:"st.motion.motion.active", backgroundColor:"#ff0000"
            }
            tileAttribute ("currentIP", key: "SECONDARY_CONTROL") {
             	 attributeState "currentIP", label: 'abc'
 			}
        }

		standardTile("motion", "device.motion", width: 2, height: 2) {
			state("active", label:'motion', icon:"st.motion.motion.active", backgroundColor:"#53a7c0")
			state("inactive", label:'no motion', icon:"st.motion.motion.inactive", backgroundColor:"#ffffff")
      		state("offline", label:'${name}', icon:"st.motion.motion.inactive", backgroundColor:"#ff0000")
		}
        
        standardTile("restart", "device.restart", inactiveLabel: false, decoration: "flat")
        {
        	state "default", action:"restart", label: "Restart", displayName: "Restart"
        }
        
        standardTile("refresh", "device.refresh", inactiveLabel: false, decoration: "flat")
        {
        	state "default", action:"refresh.refresh", icon: "st.secondary.refresh"
        }
        
		valueTile("temperature", "device.temperature", width: 1, height: 1)
        {
            state "temperature", label:'${currentValue}° CPU', unit: "F",
            backgroundColors:[
                [value: 25, color: "#153591"],
                [value: 35, color: "#1e9cbb"],
                [value: 47, color: "#90d2a7"],
                [value: 59, color: "#44b621"],
                [value: 67, color: "#f1d801"],
                [value: 76, color: "#d04e00"],
                [value: 77, color: "#bc2323"]
            ]
        }
        
        valueTile("cpuPercentage", "device.cpuPercentage", inactiveLabel: false)
        {
        	state "default", label:'${currentValue}% CPU', unit:"Percentage",
            backgroundColors:[
                [value: 31, color: "#153591"],
                [value: 44, color: "#1e9cbb"],
                [value: 59, color: "#90d2a7"],
                [value: 74, color: "#44b621"],
                [value: 84, color: "#f1d801"],
                [value: 95, color: "#d04e00"],
                [value: 96, color: "#bc2323"]
            ]
        }
        
        valueTile("memory", "device.memory", width: 1, height: 1) {
        	state "default", label:'${currentValue} MB', unit:"MB",
            backgroundColors:[
                [value: 353, color: "#153591"],
                [value: 287, color: "#1e9cbb"],
                [value: 210, color: "#90d2a7"],
                [value: 133, color: "#44b621"],
                [value: 82, color: "#f1d801"],
                [value: 26, color: "#d04e00"],
                [value: 20, color: "#bc2323"]
            ]
        }
        
        valueTile("diskUsage", "device.diskUsage", width: 1, height: 1) {
        	state "default", label:'${currentValue}% Disk', unit:"Percent",
            backgroundColors:[
                [value: 31, color: "#153591"],
                [value: 44, color: "#1e9cbb"],
                [value: 59, color: "#90d2a7"],
                [value: 74, color: "#44b621"],
                [value: 84, color: "#f1d801"],
                [value: 95, color: "#d04e00"],
                [value: 96, color: "#bc2323"]
            ]
        }

        main "motion"
        details([
        	"rich-control"
            , "temperature"
            , "cpuPercentage"
            , "memory"
            , "diskUsage"
            , "restart"
            , "refresh"])
    }
}

// parse events into attributes
def parse(String description) {
	def result = []
    def msg = parseLanMessage(description)
    def json = msg.json
	def headerString = msg.header
    
	// log.debug "parsing some stuff. ${headerString}"
	unschedule("setOffline")

	// sendEvent(name: "switch", value: "on")
	if (headerString?.contains("SID: uuid:")) {
    	log.debug "got sid"
		def sid = (headerString =~ /SID: uuid:.*/) ? ( headerString =~ /SID: uuid:.*/)[0] : "0"
		sid -= "SID: uuid:".trim()

		updateDataValue("subscriptionId", sid)
	}
    
    def bodyString = msg.body
    if (bodyString && msg.headers["CONTENT-TYPE"]?.contains("xml")) {
        def body = new XmlSlurper().parseText(bodyString)
        if (body?.Body?.SetBinaryStateResponse?.BinaryState?.text()) {
            log.trace "Got SetBinaryStateResponse = ${body?.Body?.SetBinaryStateResponse?.BinaryState?.text()}"
        } 
        else if (body?.property?.BinaryState?.text()) {
            def value = body?.property?.BinaryState?.text().toInteger() == 1 ? "active" : "inactive"
            log.debug "Notify - BinaryState = ${value}"
            result << createEvent(name: "motion", value: value, descriptionText: "Motion is ${value}")
        } 
        else if (body?.property?.TimeZoneNotification?.text()) {
            log.debug "Notify: TimeZoneNotification = ${body?.property?.TimeZoneNotification?.text()}"
        }
    }	
    
	if (json){
    	log.debug "Computer is ON"
   		sendEvent(name: "switch", value: "on")
        
        if (result.containsKey("cpu_temp")) {
            result << createEvent(name: "temperature", value: json.cpu_temp)
        }

        if (result.containsKey("cpu_perc")) {
            result << createEvent(name: "cpuPercentage", value: json.cpu_perc)
        }

        if (result.containsKey("mem_avail")) {
            log.debug "mem_avail: ${json.mem_avail}"
            result << createEvent(name: "memory", value: json.mem_avail)
        }

        if (result.containsKey("disk_usage")) {
            log.debug "disk_usage: ${json.disk_usage}"
            result << createEvent(name: "diskUsage", value: json.disk_usage)
        }

        if(result.containsKey("motion")){
            log.debug "motion: ${json.motion}"
            result << createEvent(name: "motion", value: json.motion)
        }
    }
    
    result
}

// handle commands
def configure() {
    log.debug "Configuring Reporting and Bindings."
}

def poll() {
	log.debug "Executing 'poll'"
    getStatus()
}

def refresh() {   
	sendEvent(name: "switch", value: "off")
	log.debug "Executing 'refresh'"
    setDeviceNetworkId(ip, port)
    [unsubscribe(), subscribe(), getStatus()]
}

def restart(){
	log.debug "Restart was pressed"
    def uri = "/macros/reboot"
    postAction(uri)
}

def subscribe() {
	subscribe(getHostAddress())
}
	
def subscribe(hostAddress) {
    log.debug "Executing 'subscribe()'"
    setIpAddress()
    subscribeAction("/motion", "")
}

def subscribe(ip, port) {
	def existingIp = getDataValue("ip")
	def existingPort = getDataValue("port")
	if (ip && ip != existingIp) {
		log.debug "Updating ip from $existingIp to $ip"
        updateDataValue("ip", ip)
    	def ipvalue = convertHexToIP(getDataValue("ip"))
    	sendEvent(name: "currentIP", value: ipvalue, descriptionText: "IP changed to ${ipvalue}")
	}
	if (port && port != existingPort) {
		log.debug "Updating port from $existingPort to $port"
		updateDataValue("port", port)
	}

	subscribe("${ip}:${port}")
 }

def resubscribe() {
    log.debug "Executing 'resubscribe()'"

    def sid = getDeviceDataByName("subscriptionId")
	def headers = [:]
    
    headers.put("HOST", getHostAddress())
    headers.put("SID", "uuid:${sid}")
    headers.put("TIMEOUT", "Second-86400")
    
  	def hubAction = new physicalgraph.device.HubAction(
    	method: "SUBSCRIBE",
    	path: "/motion",
    	headers: headers
  	)
    
    return hubAction
}

def unsubscribe() {
    def sid = getDeviceDataByName("subscriptionId")
	def headers = [:]
    
	log.debug "unsubscribing from subscription id ${sid}"

	headers.put("HOST", getHostAddress())
    headers.put("SID", "uuid:${sid}")
    
  	def hubAction = new physicalgraph.device.HubAction(
    	method: "UNSUBSCRIBE",
    	path: "/motion",
    	headers: headers
  	)
    return hubAction
}

def setIpAddress(){
    def devip = getDataValue("ip")
    def ipvalue = convertHexToIP(devip)
    
    log.debug "Updating ip to $devip"
    sendEvent(name: "currentIP", value: ipvalue, descriptionText: "IP changed to ${ipvalue}")    
}

// get various stats pieces from the raspberry pi
private getStatus() {
	if (device.currentValue("currentIP") != "Offline")
    	runIn(30, setOffline)
        
    postAction("/")
}

// ------------------------------------------------------------------

private postAction(uri){
  setDeviceNetworkId(ip, port)  
  
  def userpass = encodeCredentials(username, password)
  def headers = makeHeaders(userpass)
  
  def hubAction = new physicalgraph.device.HubAction(
    method: "POST",
    path: uri,
    headers: headers
  )
  
  log.debug("Executing hubAction on " + getHostAddress() + " with uri ${uri}")
  
  hubAction    
}

// ------------------------------------------------------------------
// Helper methods
// ------------------------------------------------------------------

private subscribeAction(path, callbackPath="") {
    log.trace "subscribe($path, $callbackPath)"
    def address = getCallBackAddress()
    def ip = getHostAddress()

    def result = new physicalgraph.device.HubAction(
        method: "SUBSCRIBE",
        path: path,
        headers: [
            HOST: ip,
            CALLBACK: "<http://${address}/$callbackPath>", // does not need to be motion, either...
            NT: "upnp:event", // does not need to be upnp:event
            TIMEOUT: "Second-86400"
        ]
    )

    return result
}

def setOffline(){
	log.debug "setting offline"
	sendEvent(name: "motion", value: "offline", descriptionText: "The device is offline")
}

// gets the address of the hub
private getCallBackAddress() {
    return device.hub.getDataValue("localIP") + ":" + device.hub.getDataValue("localSrvPortTCP")
}

private encodeCredentials(username, password){
	def userpassascii = "${username}:${password}"
    def userpass = "Basic " + userpassascii.encodeAsBase64().toString()
    //log.debug "ASCII credentials are ${userpassascii}"
    //log.debug "Credentials are ${userpass}"
    return userpass
}

private makeHeaders(userpass){
	log.debug "Making headers"
    
    def headers = [:]
    headers.put("HOST", getHostAddress())
    headers.put("Authorization", userpass)
    
    return headers
}

private setDeviceNetworkId(ip, port){
  	def iphex = convertIPtoHex(ip)
  	def porthex = convertPortToHex(port)
    
    if (device.deviceNetworkId != "$iphex:$porthex") {
        device.deviceNetworkId = "$iphex:$porthex"
	  	log.debug "Device Network Id set to ${iphex}:${porthex}"
    }
}

// gets the address of the device
private getHostAddress() {
    def devip = getDataValue("ip")
    def devport = getDataValue("port")

    if (!devip || !devport) {
    	log.debug "device does not have an ip address"
        def parts = device.deviceNetworkId.split(":")
        if (parts.length == 2) {
            devip = parts[0]
            devport = parts[1]
        } else {
            log.warn "Can't figure out ip and port for device: ${device.id}"
        }
    }
	devip = convertHexToIP(devip) 
    devport = convertHexToInt(devport)
    updateDataValue("ip", convertIPtoHex(devip))
    updateDataValue("port", convertPortToHex(devport))
    log.debug "Using IP: ${devip} and port: ${devport} for device: ${device.id}"
    return devip + ":" + devport
}

private String convertIPtoHex(ipAddress) { 
    String hex = ipAddress.tokenize( '.' ).collect {  String.format( '%02x', it.toInteger() ) }.join()
    return hex
}

private String convertPortToHex(port) {
	String hexport = port.toString().format( '%04x', port.toInteger() )
    return hexport
}

private Integer convertHexToInt(hex) {
    return Integer.parseInt(hex,16)
}

private String convertHexToIP(hex) {
    return [convertHexToInt(hex[0..1]),convertHexToInt(hex[2..3]),convertHexToInt(hex[4..5]),convertHexToInt(hex[6..7])].join(".")
}
