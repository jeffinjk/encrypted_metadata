# save as extract_metadata.py
from PIL import Image

def extract_metadata_from_png(png_path):
    """
    Reads embedded metadata from a PNG image.
    Returns a dictionary.
    """
    img = Image.open(png_path)
    metadata = img.info
    filtered_metadata = {k: v for k, v in metadata.items() if k not in ["dpi", "transparency"]}
    return filtered_metadata

if __name__ == "__main__":
    png_image = "sett.png"  # Replace with your PNG path
    metadata = extract_metadata_from_png(png_image)

    print("Retrieved metadata:")
    for k, v in metadata.items():
        print(f"{k}: {v}")
