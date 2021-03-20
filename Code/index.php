<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="css/styles.css">
    <title>Welcome!</title>
    <script>
    function fileValidation() { 
            var fileInput =  
                document.getElementById('logFile'); 
              
            var filePath = fileInput.value; 
          
            // Allowing file type 
            var allowedExtensions =  
                    /(\.txt|\.json)$/i; 
              
            if (!allowedExtensions.exec(filePath)) { 
                alert('Log of Cowrie must be submitted in Json or Txt extension'); 
                fileInput.value = ''; 
                return false; 
            }  
        } 
    </script>
</head>
<body>
    <div class="form">
        <form action="./process.php" method="post" enctype="multipart/form-data">
            <div class=logo>
                <img src="images/logo.png" alt="Cowrie" height="400px">
            </div>
            <br>
            <p>Insert your JSON formatted Cowrie Log!</p>
            <br>
            <div class="log">
                <input type="file" accept=".txt,.json" name="logFile" id="logFile" onchange="return fileValidation()">
            </div>
            <br>
            <div class="pencet">
                <button type="submit">Submit</button>
            </div>
            <tr>
                <td>
                    <label for="error" style="color:red">
                        <?=@$_GET['error'];?>
                    </label>
                </td>
            </tr>
        </form>
    </div>
</body>
</html>