# save as embed_metadata.py
from PIL import Image, PngImagePlugin
import os

def process_image_for_metadata(input_path, metadata, output_path=None):
    """
    Converts any image to PNG, embeds metadata, returns output path.
    """
    if output_path is None:
        base_name = os.path.splitext(os.path.basename(input_path))[0]
        output_path = f"{base_name}.png"

    img = Image.open(input_path).convert("RGB")

    png_info = PngImagePlugin.PngInfo()
    for key, value in metadata.items():
        png_info.add_text(key, str(value))

    img.save(output_path, "PNG", pnginfo=png_info)
    return output_path

if __name__ == "__main__":
    metadata_example = {
        "CaseID": "CASE12345",
        "Modality": "MRI",
        "Organ": "Brain",
        "Disease": "Glioblastoma",
        "SeverityIndex": 5,
        "UrgencyZone": "Red",
        "Description": "Large lesion in left frontal lobe"
    }

    input_image = "mri.jpg"  # Replace with your image path
    output_png = process_image_for_metadata(input_image, metadata_example)
    print(f"PNG saved with metadata: {output_png}")
