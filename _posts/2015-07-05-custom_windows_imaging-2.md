---
layout: post
title:  "Custom Windows Imaging - Part II: Image Development Environment"
date:   2015-08-02 12:00:00
categories: technical
tags: custom windows image aik vm
---
Now that we know the broad strokes of creating custom windows images (see [Part I]({{site.baseurl}}/technical/custom_windows_imaging-1.html)), we'll get into my suggestions for a development environment that will let you build and test custom images on virtual machines prior to their deployment. This part of the guide involves hardware recommendations and [Windows AIK](http://www.microsoft.com/en-US/Download/details.aspx?id=5753) setup and configuration.

![aik]({{ site.baseurl }}/img/2015-08-02/aik.png)

### **Hardware Recommendations**
The [Windows AIK](http://www.microsoft.com/en-US/Download/details.aspx?id=5753) is fairly lightweight and can be installed on Windows 7/Server 2008 or later (it's designed for 7/2008). As such it can easily be run on a low-spec system - I have developed custom images in [VirtualBox](https://www.virtualbox.org/) on a laptop with a 3rd gen i5 processor, 8 Gb RAM, and a 320 Gb HDD. That being said, I would highly recommend a much snappier, and dedicated machine if you can afford it. Storage speed and RAM are key here since we will be running a lot of virtual machines, storing a lot of virtual snapshots, and generating large image files. Here's what I'd recommend:

* **CPU**: 3rd Gen i7 or later (or equivalent AMD)
* **GPU**: No discrete graphics necessary.
* **RAM**: 16 Gb - you may consider getting more if you plan on using this system for other virtualization applications.
* **Storage**: 1 Tb Solid State Storage - storage speed is key here so SSDs are a necessity. To save money and achieve even faster speeds, consider [RAIDing a few smaller SSDs](http://www.pcworld.com/article/2365767/feed-your-greed-for-speed-by-installing-ssds-in-raid-0.html). For high fidelity applications you may want to use a redundant RAID scheme since the SSDs will eventually fail under heavy use.
* **DVD Drive**: Burning the images to DVD goes much faster with a x8 or x16 drive. Of course, you may not even need a DVD drive if you'll be [creating bootable USB media](https://rufus.akeo.ie/).

### **Server Setup**
Now that you've got the hardware for your new image development server, you'll need an operating system and some virtualization software. I would recommend Windows Server 2008 R2 - simply because this is the OS that the AIK was designed for. As far as virtualization software goes, I'd recommend one of two options:

1. [VMware Workstation](https://www.vmware.com/products/workstation) - VMware has been in the business of virtualization a long time and develops high-quality products. Workstation features very robust VM configuration, allowing a lot of advanced configuration and a very sleek and intuitive UI. The Workstation edition isn't free so this is the more expensive option.
2. [VirtualBox](https://www.virtualbox.org/) - this is the more economical option and my first choice. VirtualBox is open source, and can accomplish anything you'll need to build basic custom images. It lacks some of the [more advanced features and polished feel](http://www.infoworld.com/article/2888046/virtualization/desktop-virtualization-review-vmware-workstation-vs-oracle-virtualbox.html) that Workstation offers but will be more than enough for most basic builds.

If you opted for solid state storage, image creation and virtual machine deployment will be very quick, especially with the right RAID configuration. Performance can be optimized by creating a physically or logically separate operating system partition. That way OS reads/writes do not get in the way of VM or image creation reads/writes.

### **AIK Setup**

Now that you've got your hardware, OS, and virtualization environment, it's time to install the AIK and build a Windows PE image with imageX. The AIK can be downloaded [here](https://www.microsoft.com/en-us/download/details.aspx?id=5753) from the Microsoft download center. It ships as an iso image so you'll have to burn it to DVD or expand it with 3rd party software and transfer it to your new server. Installation is pretty straightforward and shouldn't run into any problems on a fresh install of Server 2008.

As you may remember from [Part I]({{site.baseurl}}/technical/custom_windows_imaging-1.html), we'll need to create a [WinPE](https://en.wikipedia.org/wiki/Windows_Preinstallation_Environment) CD with [imageX](https://technet.microsoft.com/en-us/library/cc722145(v=ws.10).aspx) included in order to capture [WIM](https://technet.microsoft.com/en-us/library/cc749478(v=ws.10).aspx) images of our configured VMs. Microsoft has a [video guide](https://technet.microsoft.com/en-us/windows/ff657747) for this posted on TechNet that I followed - here are the steps:

1. Open the Windows PE Deployment Tools Command Prompt from the Start menu as and Administrator.
![command_prompt]({{ site.baseurl }}/img/2015-08-02/command_prompt.png)
2. Use the `copype` script to generate the WinPE files by running `copype x86 C:\winpex86`. This script packages a WinPE WIM image with all of the necessary files to create a bootable PE iso folder and places them in `C:\winpex86`.
3. Next, you'll need to replace the `boot.wim` file in `C:\winpex86\ISO\sources\` with the correct WinPE WIM which is located in `C:\winpex86\`. Run `copy C:\winpex86\winpe.wim C:\winpex86\ISO\sources\boot.wim`.
4. Copy the imageX tool to the root of the ISO image so we can use it when we boot into the Preinstallation Environment. Run `copy "C:\Program Files\Windows AIK\Tools\x86\imagex.exe" C:\winpex86\ISO\`.
5. Finally, package the `ISO` directory into a bootable disk image by running `oscdimg -n -bC:\winpex86\etfsboot.com C:\winpex86\ISO C:\winpex86\winpex86.iso`. This will generate the ISO file `winpex86.iso` with a boot image from `C:\winpex86\etfsboot.com` from the files located in `C:\winpex86\ISO\`. This command may take a few moments.

Now that you have your bootable WinPE ISO, we should have everything we need to start building custom images. Check back for the final part of this series when I describe the process of [syspreping](https://en.wikipedia.org/wiki/Sysprep) a custom built system, capturing an image of it with [imageX](https://technet.microsoft.com/en-us/library/cc722145(v=ws.10).aspx), and packing it all into a custom installation disk.

<div class="recipe" markdown="1">
### **TL;DR**
When building a virtualization server for custom Windows image creation:

* Storage speed is key - I *highly* recommend solid state storage.
* You have a couple couple of options for virtualization software but I recommend [VirtualBox](https://www.virtualbox.org/).
* Once you install the [Windows AIK](http://www.microsoft.com/en-US/Download/details.aspx?id=5753) you'll want to create a [WinPE](https://en.wikipedia.org/wiki/Windows_Preinstallation_Environment) disk with [imageX](https://technet.microsoft.com/en-us/library/cc722145(v=ws.10).aspx) built in so that you can capture [WIM](https://technet.microsoft.com/en-us/library/cc749478(v=ws.10).aspx) images.
</div>
