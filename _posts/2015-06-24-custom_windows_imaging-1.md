---
layout: post
title:  "Custom Windows Images - Part I: Introduction"
date:   2015-06-24 17:00:00
categories: technical
tags: custom windows image aik
---

My work at Raytheon often involved working with remote systems located overseas. These systems were designed to be nearly identical to one another - with like hardware, software, and physical configuration. As an added measure of complication, there is no means of accessing these systems remotely - any changes, IA configuration, or compliance verification had to be done through the proxy of a local system administrator. If my team wanted to make an IA change to the systems, we had to develop detailed instructions and oversee the deployment of these changes, working with each sys admin individually - there was no doing it ourselves. If a piece of hardware failed and needed to be replaced, it would have to be configured to our security standards by the sys admins by hand. There had to be a better way of standardizing these systems, hadn't there? Enter the Windows [Automated Installation Kit (AIK)](http://www.microsoft.com/en-US/Download/details.aspx?id=5753).

![Windows]({{ site.baseurl }}/img/2015-06-24/windows.png)

###**The Goal**
Let's step back a bit and think about what we're trying to accomplish.

Imagine we're provisioning some brand new, bare metal systems with Windows 7 - our theoretical network has experienced a recent increase in the number of concurrent users and we need to add some more workstations to accommodate. *No big deal, right? We'll just install Windows 7 and then configure each system individually.* But what if we need to install MATLAB, and Microsoft Office, and Adobe Creative Suite, and Firefox, and Antivirus, and corporate branding, and the new logon banner that legal approved, and we need to configure security settings (see [STIG](https://en.wikipedia.org/wiki/Security_Technical_Implementation_Guide)), and ...

Now imaging and deploying these new workstations goes from a matter of hours to days or weeks of mindless, repetitive work. *Okay, so why don't we build a reference system on like hardware and then copy the hard drive, bit for bit, onto the new systems (see [Taking a Windows System Image](http://www.howtogeek.com/howto/4241/how-to-create-a-system-image-in-windows-7/))?*

It turns out there are a number of problems with that strategy too:

* The new system you're imaging needs to have EXACTLY the same hardware configuration as the old one
* The license key on the new system will be identical to the reference computer (not a problem if you have [volume licensing](https://www.microsoft.com/en-us/Licensing/licensing-programs/licensing-programs.aspx))
* You'll run into the [Duplicate SID Problem](http://blogs.technet.com/b/markrussinovich/archive/2009/11/03/3291024.aspx)

So we need a way to capture the all of the installed software, files, and configuration settings on a reference system and stuff it into an installation disk that, when booted from, will install our custom image, generate a new SID, and allow you to enter a new product key and re-activate.

###**The Process**

To overcome the duplicate SID problem, we'll use Microsoft's built-in (although somewhat hidden) system preparation tool [sysprep](https://en.wikipedia.org/wiki/Sysprep). Using sysprep you can revert a system to an "out of the box" state, queueing the first boot SID generation script, generating a new system name, rerunning hardware detection, and clearing out a number of other installation-dependent system settings to be regenerated on the next boot.

Now at this point, if we were using like hardware, we could simply copy an exact image of the sysprepped hard drive to the new system. *But what if the purchasing department decides they want to start buying laptops with half the disk space to cut costs? We'll have avoided a number of pitfalls by sysprepping but our image will be too big to fit on the new systems and we'll have to start over again.*

To solve this problem, we'll use [imagex](https://technet.microsoft.com/en-us/library/cc722145(v=ws.10).aspx), a program from the Windows AIK, to capture a [Windows Imaging File Format (WIM)](https://technet.microsoft.com/en-us/library/cc749478(v=ws.10).aspx) image of our drive. A WIM image is filesystem based, rather than bits based like an exact copy of a drive would be - see the image from [TechNet](https://technet.microsoft.com/en-us/library/cc749478(v=ws.10).aspx) below.

![Wim File from TechNet]({{ site.baseurl }}/img/2015-06-24/wim.gif)

The WIM file format allows us to capture an image of our system that is only as big as it needs to be to contain the additional programs and files that we add to our reference computer. *But WIM isn't a very common image format - won't it be complicated to apply this image to our new systems? How will our sysadmins know how to do it?*

The final step in our image creation process is roll our custom WIM file into a Windows installation disk so that you can simply boot from the disk and install your custom image just as you would install a stock version of Windows. Windows installation media actually contains a default WIM image that's applied to the system when it's installed. By unpacking a Windows ISO, replacing the right WIM file, and repacking using [oscdimg](https://technet.microsoft.com/en-us/library/cc749036(v=ws.10).aspx) (another AIK tool), we'll have successfully created our custom windows image.

###**TL;DR**

The broad strokes of using the AIK to create custom installation media are actually fairly simple:

<div class="recipe" markdown="1">
1. Install and configure Windows on a reference computer, adding all your custom software and configuration settings.
2. [Sysprep](https://en.wikipedia.org/wiki/Sysprep) the reference computer to generalize the image.
3. Capture a [WIM](https://technet.microsoft.com/en-us/library/cc749478(v=ws.10).aspx) image of the system using [imagex](https://technet.microsoft.com/en-us/library/cc722145(v=ws.10).aspx).
4. Unpack a stock Windows ISO, replace the install WIM, and repack it using [oscdimg](https://technet.microsoft.com/en-us/library/cc749036(v=ws.10).aspx).
</div>

---

##**Coming Soon...**
In the next part of my custom Windows imaging guide, we'll dive into the Windows AIK and I'll talk about setting up a robust imaging platform using virtualization that you can use to develop, image, and deploy custom Windows installations.

---

_**Disclaimer:** I am not a Microsoft employee. This is not an official Microsoft forum or supported process - simply a procedure that I use._