import argparse
import logging.config

from setting.LoggerConf import MY_LOGGING_CONFIG

import sniffer

logging.config.dictConfig(MY_LOGGING_CONFIG)
logger = logging.getLogger(__name__)


def snifThread(input_file,input_interface,output_mode,output):
    try:
        session_instance = sniffer.createSniffer(
        input_file,
        input_interface,
        output_mode,
        output)

        session_instance.start()

        try:
            session_instance.join()
        except KeyboardInterrupt:
            session_instance.stop()
        finally:
            session_instance.join()

    except Exception as e:
        logger.info("Error while calling sniffer.")
        logger.exception(e)

    print("finish")

def main():
    parser = argparse.ArgumentParser(prog="mlridin",description='A Machine Learning based Real-time Intrusion Detection System in Network')

    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument('-i','--interface',
    dest="input_interface",
    help="This interface will be used to capture traffic in order to convert it into the flow.")

    group.add_argument('-f','--file',
    dest="input_file",
    help="This file will be converted to the flow.")

    parser.add_argument('-c','--csv','--flow',action='store_const',const="flow", 
    dest="output_mode",
    help="The output will be store in the form of csv in output file.")

    parser.add_argument('--output-file',default='flow.csv',
    dest="output",
    help="default: %(default)s, The file output will be written to.")

    args = parser.parse_args()

    snifThread(args.input_file,args.input_interface,args.output_mode,args.output)

if __name__ == "__main__":
    main()