<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="css/styles.css">
    <title>Welcome!</title>
</head>
<body>
    <div>
        <div class=logo>
            <img src="images/logo.png" alt="Cowrie" height="400px">
        </div>
        <br>
        <p>Here is your report!</p>
        <p>Click the file to download it!</p>
        <a href="<?=$_GET['result'];?>" download>
            <img src="images/excel.png" alt="result" height="80px">
        </a>
    </div>
</body>
</html>