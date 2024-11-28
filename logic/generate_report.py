import sys
import datetime
import json

def format_report(alert_type, report_details):
    report = f"Alert Type: {alert_type.replace('_', ' ').capitalize()}\n"
    report += "--------------------------------------------\n"
    report += f"Report Details: {report_details}\n"
    
    return report

def generate_detailed_report(alert_type, report_details):
    current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    report_header = f"Detailed Report Generated at {current_time}\n"
    report_header += "=" * 50 + "\n"
    
    report_body = format_report(alert_type, report_details)
  
    full_report = report_header + report_body


    
    return file_name

if __name__ == "__main__":
 
    if len(sys.argv) < 3:
        print("Usage: python3 generate_report.py <alert_type> <report_details_json>")
    else:
        try:
            alert_type = sys.argv[1]
            report_details = sys.argv[2]
            
            report_file = generate_detailed_report(alert_type, report_details)
            print(f"Report successfully generated: {report_file}")
        except Exception as e:
            print(f"Error generating report: {str(e)}")



# import sys
# import datetime
# import json
# from transformers import pipeline

# def format_report(alert_type, report_details):
#     report = f"Alert Type: {alert_type.replace('_', ' ').capitalize()}\n"
#     report += "--------------------------------------------\n"
#     report += f"Report Details: {report_details}\n"
#     return report

# def generate_ai_report(report_details):
#     try:
#         summarizer = pipeline("summarization")
#         if isinstance(report_details, dict):
#             report_details = json.dumps(report_details)
        
#         summary = summarizer(report_details, max_length=100, min_length=30, do_sample=False)
#         return summary[0]['summary_text']
#     except Exception as e:
#         print(f"Error during AI report generation: {str(e)}")
#         return "AI summary generation failed."

# def generate_detailed_report(alert_type, report_details):
#     current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
#     report_header = f"Detailed Report Generated at {current_time}\n"
#     report_header += "=" * 50 + "\n"
    
#     ai_summary = generate_ai_report(report_details)
#     report_body = format_report(alert_type, ai_summary)
    
#     full_report = report_header + report_body
#     file_name = f"report_{alert_type}.txt"
    
#     try:
#         with open(file_name, 'w') as report_file:
#             report_file.write(full_report)
#         print(f"Report saved as {file_name}")
#     except Exception as e:
#         print(f"Error writing report file: {str(e)}")
    
#     return file_name

# if __name__ == "__main__":
#     try:
#         if len(sys.argv) < 3:
#             print("Usage: python3 generate_report.py <alert_type> <report_details_json>")
#         else:
#             alert_type = sys.argv[1]
#             report_details_json = sys.argv[2]

#             print(f"Raw JSON string: {report_details_json}")
#             report_details = json.loads(report_details_json)

#             print("Parsed report details:", report_details)
#             full_report = generate_detailed_report(alert_type, report_details)
#             if full_report:
#                 print(full_report)
#             else:
#                 print("Failed to generate report.")
#     except json.JSONDecodeError as e:
#         print(f"JSON parsing error: {str(e)}")
#     except Exception as e:
#         print(f"Error generating report: {str(e)}")
