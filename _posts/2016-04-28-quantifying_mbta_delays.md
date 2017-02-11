---
layout: post
title:  "Quantifying MBTA Delays"
date:   2016-04-28 10:30:00
categories: python projects mbta
excerpt_separator: <!--more-->
---
This co-op cycle I'm working at MIT Lincoln Lab. While I do really enjoy it
there and have learned a lot over the past few months, the commute sucks. Since
I live near Northeastern campus and take the MBTA in to work, it takes me about
an hour and a half each way - assuming the T is running on time. Unfortunately
it rarely ever does, and this post is about a project I came up with to
quantify all that lost time using a [Raspberry Pi], [Google's Distance Matrix
API], my phone, and [D3.js].

<!--more-->

![mbta_logo]({{ site.baseurl }}/img/mbta-delays/mbta_logo.png)

## **The Inspiration**
It seems like every year that I participate in the [CCDC](http://www.nationalccdc.org/) I end up with another Raspberry Pi that I don't know what to do with. That, coupled with the fact that I've had nearly 3 hours every day on my commute to come up with ideas for it, lead to this project. Developed entirely while riding the T, I present my personal commute delay tracker.

![raspberry_pi]({{ site.baseurl }}/img/mbta-delays/raspberry_pi.jpg)

## **Technical Details**

### **The Back End**

At the heart of this project is a REST-like application written in python with [Flask](http://flask.pocoo.org). This app maintains two endpoints:

1. `/data` - Exposes json commute data via a `GET` request
1. `/update` - Allows data update via an authenticated `POST` request with json data in the following format.

{% highlight python %}
{
  "key": "",      # A secret key used for authentication
  "action": "",   # either "depart" or "arrive"
  "location": "", # latitude and longitude
  "time": ""      # current time
}
{% endhighlight %}

The first endpoint is relatively simple:

{% highlight python %}
@app.route('/data', methods=['GET'])
@cross_origin()
def get_data():
    f = open('/path/to/data.json', 'r')
    data = json.load(f)
    f.close()

    return jsonify({'results': data})
{% endhighlight %}

Note: We have to allow [CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/Access_control_CORS) requests here since the data is fetched and rendered client side in the front end.

The second endpoint required a bit more plumbing. First, for security reasons, I wanted to validate some sort of shared key so that the filesystem of my Raspberry Pi isn't just exposed to the world.

{% highlight python %}
if data['key'] != SECRET: raise Exception()
{% endhighlight %}

Next, we need to normalize the time format.

{% highlight python %}
now = parse(time_string)
        epoch = datetime.datetime.utcfromtimestamp(0)
        time = int((now-epoch).total_seconds())
{% endhighlight %}

Finally if `action` is "depart" then we need to save the current location and time for later use. If it's "arrive", then we should calculate the time it should have taken via Google Maps for various transportation modes and save it off into `data.json`.

{% highlight python %}
action = data['action']
location = data['location']
time_string = data['time']

now = parse(time_string)
epoch = datetime.datetime.utcfromtimestamp(0)
time = int((now-epoch).total_seconds())

if action == 'depart':
    save_depart(location, time)
elif action == 'arrive':
    depart = get_depart()
    arrive = { 'location': location, 'time': time }
    results = get_expected_time(depart, arrive)
    write_data(results)
{% endhighlight %}

The key function here is `get_expected_time()`

{% highlight python %}
def get_expected_time(depart, arrive):
    results = {}

    for mode in modes:
        endpoint = 'https://maps.googleapis.com/maps/api/distancematrix/json'
        options = {
            'key': GDISTANCEMATRIX_KEY,
            'origins': depart['location'],
            'destinations': arrive['location'],
            'mode': mode,
            'departure_time': depart['time'] + 7*24*60*60,
            'units': 'imperial',
        }

        url = '{}?{}'.format(endpoint, urllib.urlencode(options))

        result = json.loads(urllib.urlopen(url).read())
        travel_time = result['rows'][0]['elements'][0]['duration']['value']

        results[mode] = (int(travel_time)+int(depart['time']))*1000

    results['depart'] = int(depart['time']*1000)
    results['arrive'] = int(arrive['time']*1000)
    return results
{% endhighlight %}

If you were looking closely, you may have noticed that I fetch transportation time one week in the future for all predictions. This is because Google's Distance Matrix API won't actually let you fetch timing data for travel that occurs in the past. This design decision was made for two reasons. First, to ensure flexibility - this way it doesn't actually matter where I start and end my trip and I don't need to provide the application with my destination when I depart. Second, to keep the T honest. Google maps is actually very good and I've found that it will sometimes account for some significant delays that I would want to hold the T accountable for. Fetching data for the future ensures we get a time that is representative of how long the T _should_ take. The full source (with a few changes) is at the bottom of this post.

I should also mention that this required some minor configuration of my home router.

#### **Logging Data**

Because I'm lazy and don't feel like writing an android app, I use an [IFTTT Maker Chanel](https://ifttt.com/maker) to send REST requests to my Raspberry Pi server from my phone. The IFTTT DO app even has nice little home screen widgets you can use register to an individual DO button. It's as simple as pressing the "depart" button when I get on the T and the "arrive" button when I get off.

![home_screen]({{ site.baseurl }}/img/mbta-delays/home_screen.jpg)

### **The Front End**

The real reason I collected all this data was so that I could write a cool D3 visualization on top of it. The website is hosted on [github pages](http://ainterr.github.io/mbta_delays/) and you can view it's source [here](https://github.com/ainterr/mbta_delays). I won't bore you with the details, but I'm a fan of D3 for quick and easy visualizations.

## **Source Code**

{% highlight python %}
#!/usr/bin/python

from flask import Flask, request, jsonify
from flask.ext.cors import cross_origin
import requests, urllib, json, datetime
from dateutil.parser import parse

app = Flask(__name__, static_url_path='')

SECRET = 'XXX'              # Fill this in with your own shared secret key
GDISTANCEMATRIX_KEY = 'XXX' # Fill this in with a valid distancematrix key

modes = [
    'transit',
    'driving',
    'bicycling',
    'walking',
]

def get_expected_time(depart, arrive):
    results = {}

    for mode in modes:
        endpoint = 'https://maps.googleapis.com/maps/api/distancematrix/json'
        options = {
            'key': GDISTANCEMATRIX_KEY,
            'origins': depart['location'],
            'destinations': arrive['location'],
            'mode': mode,
            # We have to add 1 week to the departure time because the
            # distancematrix API won't let you specify times in the past for
            # driving, walking, or bicycling directions.
            'departure_time': depart['time'] + 7*24*60*60,
            'units': 'imperial',
        }

        url = '{}?{}'.format(endpoint, urllib.urlencode(options))

        result = json.loads(urllib.urlopen(url).read())
        travel_time = result['rows'][0]['elements'][0]['duration']['value']

        results[mode] = (int(travel_time)+int(depart['time']))*1000

    results['depart'] = int(depart['time']*1000)
    results['arrive'] = int(arrive['time']*1000)
    return results

def save_depart(location, time):
    f = open('/home/pi/server/depart.json', 'r')
    data = { "location": location, "time": time }
    f.close()

    f = open('/home/pi/server/depart.json', 'w')
    f.write(json.dumps(data))
    f.close()

def get_depart():
    f = open('/home/pi/server/depart.json', 'r')
    depart = json.load(f)
    f.close()

    return depart

def write_data(results):
    f = open('/home/pi/server/data.json', 'r')
    data = json.load(f)
    f.close()

    data.append(results)

    f = open('/home/pi/server/data.json', 'w')
    data_string = json.dumps(data, sort_keys=True, indent=4, separators=(',', ': '))
    f.write(data_string)
    f.close()

@app.route('/update', methods=['POST'])
def update():
    try:
        data = request.json

        if data['key'] != SECRET: raise Exception()
        action = data['action']
        location = data['location']
        time_string = data['time']

        now = parse(time_string)
        epoch = datetime.datetime.utcfromtimestamp(0)
        time = int((now-epoch).total_seconds())

        if action == 'depart':
            save_depart(location, time)
        elif action == 'arrive':
            depart = get_depart()
            arrive = { 'location': location, 'time': time }
            results = get_expected_time(depart, arrive)
            write_data(results)
        else:
            raise Exception()

        return jsonify({'response':'logged successfully'})
    except Exception as e:
        print(e)
        return jsonify({'response':'invalid request'})

@app.route('/data', methods=['GET'])
@cross_origin()
def get_data():
    f = open('/home/pi/server/data.json', 'r')
    data = json.load(f)
    f.close()

    return jsonify({'results': data})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port='8888')
{% endhighlight %}

_**Disclaimer:** I am not affiliated with the MBTA in any way. This data is a reflection of my personal experience - gathered using precise location data and Google Maps predictions for various transportation modes._

[Raspberry Pi]: https://www.raspberrypi.org/
[Google's Distance Matrix API]: https://developers.google.com/maps/documentation/distance-matrix/
[D3.js]: http://d3js.org
