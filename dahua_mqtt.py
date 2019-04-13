"""
Dahua IP Camera events to MQTT app. Implemented from: https://github.com/johnnyletrois/dahua-watch

Example configuration:

DahuaMQTT:
  class: DahuaMQTT
  module: dahua_mqtt
  cameras:
    - host: 192.168.0.1
      port: 80
      user: user
      pass: pass
      topic: cameras/1
      events: VideoMotion,VideoBlind,VideoLoss,AlarmLocal,....
    - host: 192.168.0.2
      port: 80
      user: user
      pass: pass
      topic: cameras/2
      events: VideoMotion,VideoBlind,VideoLoss,AlarmLocal,....

App sends two MQTT topics:
First MQTT topic will be: cameras/1/<event>, ex: cameras/1/VideoMotion and payload will be action: Start or Stop
Second MQTT topic will be: cameras/1, ex: cameras/1 and payload will be data received from camera in JSON format

According to the API docs, these events are available: (availability depends on your device and firmware)
	VideoMotion: motion detection event
	VideoLoss: video loss detection event
	VideoBlind: video blind detection event.
	AlarmLocal: alarm detection event.
	CrossLineDetection: tripwire event
	CrossRegionDetection: intrusion event
	LeftDetection: abandoned object detection
	TakenAwayDetection: missing object detection
	VideoAbnormalDetection: scene change event
	FaceDetection: face detect event
	AudioMutation: intensity change
	AudioAnomaly: input abnormal
	VideoUnFocus: defocus detect event
	WanderDetection: loitering detection event
	RioterDetection: People Gathering event
	ParkingDetection: parking detection event
	MoveDetection: fast moving event
	MDResult: motion detection data reporting event. The motion detect window contains 18 rows and 22 columns. The event info contains motion detect data with mask of every row.
	HeatImagingTemper: temperature alarm event
"""

import appdaemon.plugins.hass.hassapi as hass
import socket
import pycurl
import time
import threading
import json
from threading import Thread

URL_TEMPLATE = "http://{host}:{port}/cgi-bin/eventManager.cgi?action=attach&codes=%5B{events}%5D"


class DahuaMQTT(hass.Hass):

	proc = None
	cameras = []
	curl_multiobj = pycurl.CurlMulti()
	num_curlobj = 0
	kill_thread = False

	def initialize(self):

		for camera in self.args["cameras"]:
			dahuacam = DahuaCamera(self, camera)
			self.cameras.append(dahuacam)
			url = URL_TEMPLATE.format(**camera)

			curlobj = pycurl.Curl()
			dahuacam.curlobj = curlobj

			curlobj.setopt(pycurl.URL, url)
			curlobj.setopt(pycurl.CONNECTTIMEOUT, 30)
			curlobj.setopt(pycurl.TCP_KEEPALIVE, 1)
			curlobj.setopt(pycurl.TCP_KEEPIDLE, 30)
			curlobj.setopt(pycurl.TCP_KEEPINTVL, 15)
			curlobj.setopt(pycurl.HTTPAUTH, pycurl.HTTPAUTH_DIGEST)
			curlobj.setopt(pycurl.USERPWD, "{0}:{1}".format(camera["user"], camera["pass"]))
			curlobj.setopt(pycurl.WRITEFUNCTION, dahuacam.on_receive)

			self.curl_multiobj.add_handle(curlobj)
			self.num_curlobj += 1

		self.log("Starting thread")
		self.proc = Thread(target=self.thread_process)
		self.proc.daemon = False
		self.proc.start()

	def terminate(self):
		if self.proc and self.proc.is_alive():
			self.log("Killing thread")
			self.kill_thread = True
			self.proc.join()

	def thread_process(self):
		while not self.kill_thread:
			ret, num_handles = self.curl_multiobj.perform()
			if ret != pycurl.E_CALL_MULTI_PERFORM:
				break

		while not self.kill_thread:
			ret = self.curl_multiobj.select(0.1)
			if ret == -1:
				self.on_timer()
				continue

			while not self.kill_thread:
				ret, num_handles = self.curl_multiobj.perform()

				if num_handles != self.num_curlobj:
					_, success, error = self.curl_multiobj.info_read()

					for curlobj in success:
						camera = next(filter(lambda x: x.curlobj == curlobj, self.cameras))
						if camera.reconnect:
							continue

						camera.on_disconnect("Success {0}".format(error))
						camera.reconnect = time.time() + 5

					for curlobj, errorno, errorstr in error:
						camera = next(filter(lambda x: x.curlobj == curlobj, self.cameras))
						if camera.reconnect:
							continue

						camera.on_disconnect("{0} ({1})".format(errorstr, errorno))
						camera.reconnect = time.time() + 5

					for camera in self.cameras:
						if camera.reconnect and camera.reconnect < time.time():
							self.curl_multiobj.remove_handle(camera.curlobj)
							self.curl_multiobj.add_handle(camera.curlobj)
							camera.reconnect = None

				if ret != pycurl.E_CALL_MULTI_PERFORM:
					break

		self.log("Thread exited")


class DahuaCamera:

	def __init__(self, hass, camera):
		self.hass = hass
		self.camera = camera
		self.curlobj = None
		self.connected = None
		self.reconnect = None

		self.alarm = None

	def on_alarm(self, state):

		# Publish two topics
		mqtt_data = {
			self.camera["topic"]: json.dumps(state),
			self.camera["topic"] + state["code"]: state["action"]
		}

		for topic, payload in mqtt_data.items():
			topic = topic.strip("/")
			self.hass.log("[{0}] Publishing MQTT. topic={1}, payload={2}".format(self.camera["host"], topic, payload))
			self.hass.call_service("mqtt/publish", topic=topic, payload=payload)

	def on_connect(self):
		self.hass.log("[{0}] OnConnect()".format(self.camera["host"]))
		self.connected = True

	def on_disconnect(self, reason):
		self.hass.log("[{0}] OnDisconnect({1})".format(self.camera["host"], reason))
		self.connected = False

	def on_receive(self, data):
		decoded_data = data.decode("utf-8", errors="ignore")
		# self.hass.log("[{0}]: {1}".format(self.camera["host"], decoded_data))

		for line in decoded_data.split("\r\n"):
			if line == "HTTP/1.1 200 OK":
				self.on_connect()

			if not line.startswith("Code="):
				continue

			try:
				alarm = dict()
				for keyval in line.split(';'):
					key, val = keyval.split('=')
					alarm[key.lower()] = val

				self.parse_event(alarm)
			except Exception as ex:
				self.hass.log("Failed to parse: {0}".format(str(ex)))

	def parse_event(self, alarm):
		# self.hass.log("[{0}] Parse Event ({1})".format(self.camera["host"], alarm))

		if alarm["code"] not in self.camera["events"].split(','):
			return

		self.on_alarm(alarm)
