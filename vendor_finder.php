#!/usr/bin/php

<?php

function get_vendor()
{
	fscanf(STDIN, "%s\n", $param);
	$mac_address=strtoupper($param);

	$url = "https://api.macvendors.com/".urlencode($mac_address);

	$ch = curl_init();
	curl_setopt($ch, CURLOPT_URL, $url);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);

	$response = curl_exec($ch);
	if($response)
	{
		$m='';

		for($idx=0; $idx < 9; $idx+=3)
			$m=$m.$mac_address[$idx].$mac_address[$idx+1];

		return "$m\t$response\n";
	} 
	else 
	{
	       	return "Not Found\n";
	}
}

if($argc == 1)
{
	echo "There is no param\n";
	return;
}

$cnt=$argv[1];

for ($ref=0; $ref < $cnt; $ref++)
{
	echo get_vendor();
	sleep(1); //free version : 2-requests per second
}

//ref, https://macvendors.com/api
?>
