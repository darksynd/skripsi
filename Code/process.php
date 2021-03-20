<?php
    $logFile = isset($_FILES['logFile']) ? $_FILES['logFile'] : null;


    $error = "";

    $logFilePath = './logs/'.$logFile['name'];
    $logFileExt = pathinfo($logFilePath, PATHINFO_EXTENSION);

    echo $logFileExt;
    echo $logFilePath;

    if($logFile == null){
        $error = "JSON formatted Cowrie Log must be chosen<br/>";
        header("Location: ./index.php?error=$error");
        die();
    }
    else if($logFileExt != 'txt' && $logFileExt != 'json' ){
        $error = "JSON formatted Cowrie log must be submitted in txt or json<br/>";
        header("Location: ./index.php?error=$error");
        die();
    }

    move_uploaded_file(
        $logFile['tmp_name'],
        $logFilePath
    );

    $log = $logFile['name'];
    
    header("Location: code.py?log=$log");
?>