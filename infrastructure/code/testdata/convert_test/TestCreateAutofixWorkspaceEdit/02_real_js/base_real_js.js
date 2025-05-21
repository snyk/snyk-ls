const fs = require('fs');
const path = require('path');

// Endpoint to download an image
app.get('/download/:filename', (req, res) => {
  const filename = req.params.filename;
  const filePath = path.join(__dirname, 'uploads', filename);

  if (fs.existsSync(filePath)) {
    // Fix this issue: Path Traversal
    res.download(filePath);
  } else {
    res.status(404).send('File not found.');
  }
});
