---
layout: post
title:  "An Introduction to the Dropbox API for Python"
date:   2015-06-28 11:30:00
categories: technical
tags: python dropbox api
---
A few weeks ago, my girlfriend came home frustrated about work. She's currently on co-op at an organization that develops curricula for developing countries. She writes textbooks and lessons for students - usually math. That day, she had been tasked with renaming the thousands of image files that they add to the textbooks from one naming convention to another. She had spent nearly her entire day doing it and still had much more to do. *Why don't you just write a python script to change the file names instead of doing it by hand?*, I asked. It turns out these image files take up multiple terabytes of space on a [Dropbox](https://www.dropbox.com/) account - it wouldn't be feasible to download these files, run a script on them, and then upload them again. Luckily, theres a [Dropbox API](https://www.dropbox.com/developers/core) for python.

![dropbox]({{ site.baseurl }}/img/dropbox-api/dropbox.jpg)

### **Installing the API**
It's easiest to install the [Dropbox API](https://www.dropbox.com/developers/core) using [pip](https://pip.pypa.io/en/latest/index.html). Short for **P**ython **I**nstalls **P**ython, pip is similar to ruby's [bundler](http://bundler.io/) - it will download and install python packages for you, automatically fetching their dependencies as well. To install pip:

1. Download and run [get-pip.py](https://bootstrap.pypa.io/get-pip.py) as an administrator.
2. [Edit the PATH environment variable](http://stackoverflow.com/questions/23400030/windows-7-add-path) to include the pip install directory. By default pip installs in `[Python Dir]/Scripts/`.

Once pip is installed, you can simply run `pip install dropbox` from an administrator command prompt to install the Dropbox API. To verify that it was installed correctly, open a python command prompt and run `import dropbox` - if you don't get any errors you're good to go.

### **Create a Dropbox Application**
Dropbox requires that you register any application using their services through their developer console. To generate a new app key and secret:

1. Log into the [Dropbox Developer Console](https://www.dropbox.com/developers/apps)  
2. Click "Create App".
3. Check Dropbox API App.
4. Can your app be limited to its own folder? - No
5. What types of files does your app need access to? - All file types
6. Provide an app name and aggree to the terms of service
7. Click Create App

Copy down the App Key and App Secret from the settings page of your new app - these uniquely identify your application. Dropbox applications use [OAuth 2.0](http://oauth.net/2/) to allow access to a user's files. This means that your application must request access (and be approved) to a user's account.

### **Setup a Template for your Scripts**
The [API tutorial](https://www.dropbox.com/developers/core/start/python) guides you through the process of setting up your first script and provides some examples of commmonly used functionality. Here's a template script that you can use to get started:

{% highlight python %}
# Include the Dropbox SDK
import dropbox

# Get your app key and secret from the Dropbox developer website
app_key = 'INSERT_APP_KEY'
app_secret = 'INSERT_APP_SECRET'

# Initiate the OAuth 2.0 process
flow = dropbox.client.DropboxOAuth2FlowNoRedirect(app_key, app_secret)

# Fetch an authorization URL
authorize_url = flow.start()

# Have the user sign in and authorize this token
authorize_url = flow.start()
print '1. Go to: ' + authorize_url
print '2. Click "Allow" (you might have to log in first)'
print '3. Copy the authorization code.'
code = raw_input("Enter the authorization code here: ").strip()

# This will fail if the user enters an invalid authorization code
access_token, user_id = flow.finish(code)

# Pass the authorized token back to the dropbox client
client = dropbox.client.DropboxClient(access_token)
print 'linked account: ', client.account_info()
{% endhighlight %}

Once you add your App Key and Secret, you can use this as a template, adding your scripting below it. When launched, it will prompt you to visit the authorization link in a web browser and ask you for the authorization code that this provides. You can add your scripting below this authorization step. 

As an example, here's a script to replace all underscores with dashes in file names in your `/test/` directory:

{% highlight python %}
# Pull a list of files in a specified directory (in this case '/test/')
metadata = client.metadata('/test/')
files = []
for x in metadata["contents"]:
  if not x["is_dir"]: files.append(x["path"])

# Filter file names (in this case replace "_" with "-")
for f in files:
  client.file_move(f, f.replace("_","-"))
{% endhighlight %}

For more details on the Dropbox API's functionality, check out the [documentation](https://www.dropbox.com/developers/core/docs/python#DropboxClient).
